package iam

// The WebAuthn passkey ceremonies, ported from kagi: adding a key to the
// signed-in account, passkey-only signup, and passkey login (discoverable).
// Ceremony challenges travel in a short-lived HttpOnly cookie keyed into the
// shared cache; the credential material lives in the unified credentials
// table with the serialized webauthn.Credential as its data. Session
// issuance fires the OnUserLogin hook so hosts attach their post-login
// side effects (device remembering, new-login alerts).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/nokku-sh/nokku/internal/crypto"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

// challengeTTL bounds one registration or login ceremony.
const (
	challengeTTL       = 5 * time.Minute
	ceremonyCookieName = "webauthn_session"
)

// passkeySignupState carries the reserved account between the signup
// ceremony's begin and finish, so the user row is only created once the
// ceremony verifies. The reserved ID is the WebAuthn user handle the
// authenticator binds the credential to.
type passkeySignupState struct {
	Session *webauthn.SessionData `json:"session"`
	ID      string                `json:"id"`
	Email   string                `json:"email"`
	Name    string                `json:"name"`
}

// webUser adapts a user row to the webauthn.User interface.
type webUser struct {
	user  *db.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webUser) WebAuthnName() string                       { return u.user.Email }
func (u *webUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// passkeyFlow serves the WebAuthn ceremonies.
type passkeyFlow struct {
	svc    *Service
	wa     *webauthn.WebAuthn
	state  *state[webauthn.SessionData]
	signup *state[passkeySignupState]
}

// newPasskeyFlow builds the WebAuthn relying party. rpID comes from the
// deployment URL's host; rpOrigins lists every origin the browser may assert.
func newPasskeyFlow(svc *Service, rpOrigins []string) (*passkeyFlow, error) {
	u, err := url.Parse(svc.baseURL)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Nokku",
		RPID:          u.Hostname(),
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, err
	}
	return &passkeyFlow{
		svc:    svc,
		wa:     wa,
		state:  newState[webauthn.SessionData](svc.cache, "webauthn:session:", challengeTTL),
		signup: newState[passkeySignupState](svc.cache, "webauthn:signup:", challengeTTL),
	}, nil
}

// ceremony helpers ---------------------------------------------------------

// putCeremony stores ceremony state under a fresh id and returns it; the id
// rides to the browser in the ceremony cookie.
func (f *passkeyFlow) putCeremony(
	ctx context.Context,
	session *webauthn.SessionData,
) (string, error) {
	sid, err := crypto.RandomString(16)
	if err != nil {
		return "", err
	}
	return sid, f.state.Put(ctx, sid, *session)
}

func (f *passkeyFlow) ceremonyCookie(id string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     ceremonyCookieName,
		Value:    id,
		Path:     "/",
		Expires:  time.Now().Add(challengeTTL),
		HttpOnly: true,
		Secure:   f.svc.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

func (f *passkeyFlow) clearedCeremonyCookie() *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set dynamically from the base URL scheme
		Name:     ceremonyCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   f.svc.Secure(),
		SameSite: http.SameSiteLaxMode,
	}
}

// user helpers -------------------------------------------------------------

// webUserFor wraps a user with its stored passkey credentials.
func (f *passkeyFlow) webUserFor(ctx context.Context, u *db.User) (*webUser, error) {
	creds, err := f.svc.ListCredentialsByType(ctx, u.ID, MethodPasskey)
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		var wc webauthn.Credential
		if err := json.Unmarshal(c.Data, &wc); err != nil {
			continue
		}
		out = append(out, wc)
	}
	return &webUser{user: u, creds: out}, nil
}

// sessionUser resolves the signed-in account for the add-key surface.
func (f *passkeyFlow) sessionUser(ctx context.Context, w http.ResponseWriter) (*webUser, bool) {
	// p, ok := PrincipalFromContext(ctx)
	// if !ok {
	// 	WriteError(w, http.StatusUnauthorized, "no_session", "sign in first")
	// 	return nil, false
	// }
	u, err := f.svc.GetUser(ctx)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return nil, false
	}
	wu, err := f.webUserFor(ctx, u)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return nil, false
	}
	return wu, true
}

// upsertPasskey persists the credential material and returns its display
// name. Refreshing an existing credential (sign count, transports) keeps
// its label.
func (f *passkeyFlow) upsertPasskey(
	ctx context.Context,
	u *db.User,
	cred *webauthn.Credential,
) (string, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	subject := base64.RawURLEncoding.EncodeToString(cred.ID)
	label := ""
	if existing, err := f.svc.q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type:     string(MethodPasskey),
		Provider: "",
		Subject:  subject,
	}); err == nil {
		label = existing.Label
	}
	if label == "" {
		label = authenticatorName(cred)
	}
	_, err = f.svc.q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:       "passkey:" + subject,
		UserID:   u.ID,
		Type:     string(MethodPasskey),
		Provider: "",
		Subject:  subject,
		Data:     data,
		Label:    label,
	})
	return label, err
}

// issueSessionFor issues the user session, sets the cookie, and fires the
// OnUserLogin hook (device remembering, new-login alerts).
func (f *passkeyFlow) issueSessionFor(w http.ResponseWriter, r *http.Request, u *db.User) {
	sess, token, err := f.svc.IssueSession(r.Context(), SessionParams{
		SubjectID: u.ID,
		Kind:      KindUser,
		Method:    MethodPasskey,
		TTL:       sessionTTL,
	})
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	http.SetCookie(w, f.svc.SessionCookie(token, sess.ExpiresAt))
	if f.svc.OnUserLogin != nil {
		f.svc.OnUserLogin(w, r, u, MethodPasskey)
	}
}

// add-key ceremony ---------------------------------------------------------

// BeginRegistration starts the add-key ceremony for the signed-in account.
// Mounted behind the auth middleware.
func (f *passkeyFlow) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}

	creation, session, err := f.wa.BeginRegistration(wu)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "registration_failed", "registration failed")
		return
	}
	sid, err := f.putCeremony(ctx, session)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, creation)
}

// FinishRegistration verifies the ceremony and persists the passkey. The
// signed-in session survives: this is credential management, not a login.
func (f *passkeyFlow) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, err := f.state.Take(ctx, CookieToken(r, ceremonyCookieName))
	if err != nil {
		WriteError(
			w,
			http.StatusBadRequest,
			"invalid_or_expired_ceremony",
			"invalid or expired ceremony",
		)
		return
	}
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}

	cred, err := f.wa.FinishRegistration(wu, session, r)
	if err != nil {
		WriteError(
			w,
			http.StatusBadRequest,
			"registration_verification_failed",
			"registration verification failed",
		)
		return
	}
	name, err := f.upsertPasskey(ctx, wu.user, cred)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	f.svc.record(ctx, Event{
		Action: ActionCredentialAdded,
		Kind:   KindUser,
		Method: MethodPasskey,
		UserID: wu.user.ID,
		Email:  wu.user.Email,
	})

	http.SetCookie(w, f.clearedCeremonyCookie())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

// signup ceremony ----------------------------------------------------------

// BeginSignup starts passkey-only registration: it refuses taken emails and
// reserves the account without creating it, so an abandoned ceremony leaves
// no user row behind.
func (f *passkeyFlow) BeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		WriteError(w, http.StatusBadRequest, "bad_input", "invalid request body")
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	if email == "" {
		WriteError(w, http.StatusBadRequest, "missing_fields", "email is required")
		return
	}
	if err := emailverify.Verify(email); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_email", "please enter a valid email address")
		return
	}

	if name == "" {
		if _, local, ok := strings.Cut(email, "@"); ok && local != "" {
			name = local
		}
	}
	if _, err := f.svc.GetUserByEmail(ctx, email); err == nil {
		// Attaching a key to an existing account goes through the signed-in
		// add-key flow; public signup must never attach to someone's
		// account.
		WriteError(
			w,
			http.StatusConflict,
			"email_taken",
			"an account with this email already exists",
		)
		return
	}

	// The reserved UUID becomes the account id at finish, so it can serve
	// as the WebAuthn user handle the authenticator binds the credential
	// to.
	reserved, err := uuid.NewV7()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	reservedID := reserved.String()
	wu := &webUser{user: &db.User{ID: reservedID, Email: email, Name: name}}
	creation, session, err := f.wa.BeginRegistration(wu)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "registration_failed", "registration failed")
		return
	}
	sid, err := crypto.RandomString(16)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if err := f.signup.Put(ctx, sid, passkeySignupState{
		Session: session,
		ID:      reservedID,
		Email:   email,
		Name:    name,
	}); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, creation)
}

// FinishSignup verifies the ceremony, creates the account, persists the
// passkey, and sends the verification email. Like the password flow, the
// account signs in only after confirming the emailed link.
func (f *passkeyFlow) FinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, err := f.signup.Take(ctx, CookieToken(r, ceremonyCookieName))
	if err != nil {
		WriteError(
			w,
			http.StatusBadRequest,
			"invalid_or_expired_ceremony",
			"invalid or expired ceremony",
		)
		return
	}
	email := normalizeEmail(r.URL.Query().Get("email"))
	if email != "" && email != st.Email {
		WriteError(
			w,
			http.StatusBadRequest,
			"invalid_or_expired_ceremony",
			"invalid or expired ceremony",
		)
		return
	}

	// The ceremony's reserved ID is the account ID: the authenticator
	// registered its credential under exactly this user handle.
	wu := &webUser{user: &db.User{ID: st.ID, Email: st.Email}}
	cred, err := f.wa.FinishRegistration(wu, *st.Session, r)
	if err != nil {
		WriteError(
			w,
			http.StatusBadRequest,
			"registration_verification_failed",
			"registration verification failed",
		)
		return
	}

	u, err := f.svc.q.CreateUserWithID(ctx, &db.CreateUserWithIDParams{
		ID:    st.ID,
		Email: st.Email,
		Name:  st.Name,
	})
	if err != nil {
		// A register flow raced the same email to the store.
		WriteError(
			w,
			http.StatusConflict,
			"email_taken",
			"an account with this email already exists",
		)
		return
	}

	f.svc.record(ctx, Event{
		Action: ActionUserCreated,
		Kind:   KindUser,
		UserID: u.ID,
		Email:  u.Email,
	})

	if _, err := f.upsertPasskey(ctx, u, cred); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	f.svc.record(ctx, Event{
		Action: ActionCredentialAdded,
		Kind:   KindUser,
		Method: MethodPasskey,
		UserID: u.ID,
		Email:  u.Email,
	})

	// Mirror the register flow: the account starts unverified and the
	// emailed link fixes that. No session is issued until then.
	if f.svc.OnPasskeySignup != nil {
		f.svc.OnPasskeySignup(r, u)
	}

	http.SetCookie(w, f.clearedCeremonyCookie())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "verification_required"})
}

// login ceremony -----------------------------------------------------------

// BeginLogin starts the login ceremony. Passkey (usernameless) login uses
// discoverable credentials; the UI sends no body.
func (f *passkeyFlow) BeginLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	assertion, session, err := f.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "login_failed", "login failed")
		return
	}
	sid, err := f.putCeremony(ctx, session)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, assertion)
}

// FinishLogin verifies the ceremony, refreshes the credential's sign count,
// and issues a session.
func (f *passkeyFlow) FinishLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, err := f.state.Take(ctx, CookieToken(r, ceremonyCookieName))
	if err != nil {
		WriteError(
			w,
			http.StatusBadRequest,
			"invalid_or_expired_ceremony",
			"invalid or expired ceremony",
		)
		return
	}

	var u *db.User
	var cred *webauthn.Credential

	if len(session.UserID) > 0 {
		// A non-discoverable begin resolved the email to a user; the
		// assertion must belong to that user.
		candidate, err := f.svc.GetUserByID(ctx, string(session.UserID))
		if err != nil {
			WriteError(
				w,
				http.StatusBadRequest,
				"login_verification_failed",
				"login verification failed",
			)
			return
		}
		wu, err := f.webUserFor(ctx, candidate)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		verified, err := f.wa.FinishLogin(wu, session, r)
		if err != nil {
			WriteError(
				w,
				http.StatusBadRequest,
				"login_verification_failed",
				"login verification failed",
			)
			return
		}
		cred = verified
		u = candidate
	} else {
		// Discoverable login: the credential names its user via the
		// user handle.
		found, verified, err := f.wa.FinishPasskeyLogin(f.discoverableUser(ctx), session, r)
		if err != nil {
			WriteError(
				w,
				http.StatusBadRequest,
				"login_verification_failed",
				"login verification failed",
			)
			return
		}
		adapter, ok := found.(*webUser)
		if !ok {
			WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		u = adapter.user
		cred = verified
	}

	if _, err := f.upsertPasskey(ctx, u, cred); err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if !u.Active {
		WriteError(w, http.StatusForbidden, "inactive", "this account has been deactivated")
		return
	}
	if !u.EmailVerified {
		WriteError(
			w,
			http.StatusForbidden,
			"email_unverified",
			"verify your email address before signing in",
		)
		return
	}

	f.svc.record(ctx, Event{
		Action: ActionLoginSucceeded,
		Kind:   KindUser,
		Method: MethodPasskey,
		UserID: u.ID,
		Email:  u.Email,
	})
	http.SetCookie(w, f.clearedCeremonyCookie())
	f.issueSessionFor(w, r, u)
}

// discoverableUser resolves a user for usernameless login, first by the
// user handle captured at registration, then by credential ID.
func (f *passkeyFlow) discoverableUser(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) > 0 {
			if u, err := f.svc.GetUserByID(ctx, string(userHandle)); err == nil {
				return f.webUserFor(ctx, u)
			}
		}
		cred, err := f.svc.q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
			Type:     string(MethodPasskey),
			Provider: "",
			Subject:  base64.RawURLEncoding.EncodeToString(rawID),
		})
		if err != nil {
			return nil, err
		}
		u, err := f.svc.GetUserByID(ctx, cred.UserID)
		if err != nil {
			return nil, err
		}
		return f.webUserFor(ctx, u)
	}
}
