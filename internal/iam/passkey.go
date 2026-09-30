package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

const (
	challengeTTL       = 5 * time.Minute
	ceremonyCookieName = "webauthn_session"
)

// passkeySignupState reserves the account so the user row only exists once
// the ceremony verifies. ID is the user handle the authenticator binds to.
type passkeySignupState struct {
	Session *webauthn.SessionData `json:"session"`
	ID      string                `json:"id"`
	Email   string                `json:"email"`
	Name    string                `json:"name"`
}

type webUser struct {
	user  *db.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webUser) WebAuthnName() string                       { return u.user.Email }
func (u *webUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type passkeyFlow struct {
	svc    *Service
	wa     *webauthn.WebAuthn
	state  *state[webauthn.SessionData]
	signup *state[passkeySignupState]
}

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
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
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

func (f *passkeyFlow) ceremonyCookie(id string) *http.Cookie {
	return f.svc.newCookie(ceremonyCookieName, id, time.Now().Add(challengeTTL))
}

func (f *passkeyFlow) clearedCeremonyCookie() *http.Cookie {
	return f.svc.newCookie(ceremonyCookieName, "", time.Unix(0, 0))
}

func (f *passkeyFlow) webUserFor(ctx context.Context, u *db.User) (*webUser, error) {
	creds, err := f.svc.sys.ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
		UserID: u.ID,
		Type:   string(MethodPasskey),
	})
	if err != nil {
		return nil, err
	}
	out := make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		var wc webauthn.Credential
		if err := json.Unmarshal(c.Data, &wc); err == nil {
			out = append(out, wc)
		}
	}
	return &webUser{user: u, creds: out}, nil
}

func (f *passkeyFlow) sessionUser(ctx context.Context, w http.ResponseWriter) (*webUser, bool) {
	u, err := f.svc.GetUser(ctx)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "sign in first")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	wu, err := f.webUserFor(ctx, u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return wu, true
}

// savePasskey keeps the existing label on a refresh. The upsert never moves a
// credential id to another account.
func savePasskey(ctx context.Context, q db.Querier, userID string, cred *webauthn.Credential) (string, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	subject := base64.RawURLEncoding.EncodeToString(cred.ID)
	label := authenticatorName(cred)
	if existing, err := q.FindCredentialBySubject(ctx, &db.FindCredentialBySubjectParams{
		Type:    string(MethodPasskey),
		Subject: subject,
	}); err == nil && existing.Label != "" {
		label = existing.Label
	}
	_, err = q.UpsertCredential(ctx, &db.UpsertCredentialParams{
		ID:      "passkey:" + subject,
		UserID:  userID,
		Type:    string(MethodPasskey),
		Subject: subject,
		Data:    data,
		Label:   label,
	})
	return label, err
}

func (f *passkeyFlow) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}
	creation, session, err := f.wa.BeginRegistration(wu)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	sid, err := f.state.put(ctx, *session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, creation)
}

func (f *passkeyFlow) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, err := f.state.take(ctx, cookieFromHeader(r.Header, ceremonyCookieName))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}
	cred, err := f.wa.FinishRegistration(wu, session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}
	name, err := savePasskey(ctx, f.svc.sys, wu.user.ID, cred)
	if err != nil {
		writeError(w, http.StatusBadRequest, "this passkey cannot be registered")
		return
	}
	f.svc.record(ctx, Event{
		Action: ActionCredentialAdded,
		Kind:   actor.KindUser,
		Method: MethodPasskey,
		UserID: wu.user.ID,
		Email:  wu.user.Email,
	})
	http.SetCookie(w, f.clearedCeremonyCookie())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

func (f *passkeyFlow) BeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	if err := emailverify.Verify(email, f.svc.strict); err != nil {
		writeError(w, http.StatusBadRequest, "please enter a valid email address")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	if _, err := f.svc.GetUserByEmail(ctx, email); err == nil {
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}

	st := passkeySignupState{ID: uuid.NewV7().String(), Email: email, Name: name}
	creation, session, err := f.wa.BeginRegistration(&webUser{user: &db.User{ID: st.ID, Email: email, Name: name}})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	st.Session = session
	sid, err := f.signup.put(ctx, st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, creation)
}

// FinishSignup doesn't sign in, the account must confirm its email first.
func (f *passkeyFlow) FinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, err := f.signup.take(ctx, cookieFromHeader(r.Header, ceremonyCookieName))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	cred, err := f.wa.FinishRegistration(&webUser{user: &db.User{ID: st.ID, Email: st.Email}}, *st.Session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}

	var u *db.User
	err = f.svc.conn.WithTx(ctx, func(q *db.Queries) (err error) {
		u, err = q.CreateUserWithID(ctx, &db.CreateUserWithIDParams{ID: st.ID, Email: st.Email, Name: st.Name})
		if err != nil {
			return err
		}
		_, err = savePasskey(ctx, q, u.ID, cred)
		return err
	})
	if err != nil {
		// Most likely a password signup raced the same email.
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}
	f.svc.record(
		ctx,
		Event{Action: ActionUserCreated, Kind: actor.KindUser, Method: MethodPasskey, UserID: u.ID, Email: u.Email},
	)
	if f.svc.OnPasskeySignup != nil {
		f.svc.OnPasskeySignup(r, u)
	}
	http.SetCookie(w, f.clearedCeremonyCookie())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "verification_required"})
}

func (f *passkeyFlow) BeginLogin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := f.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	sid, err := f.state.put(r.Context(), *session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, f.ceremonyCookie(sid))
	WriteJSON(w, http.StatusOK, assertion)
}

func (f *passkeyFlow) FinishLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, err := f.state.take(ctx, cookieFromHeader(r.Header, ceremonyCookieName))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	found, cred, err := f.wa.FinishPasskeyLogin(f.discoverableUser(ctx), session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "login verification failed")
		return
	}
	wu, ok := found.(*webUser)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	u := wu.user
	if _, err := savePasskey(ctx, f.svc.sys, u.ID, cred); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, f.clearedCeremonyCookie())

	cookie, err := f.svc.completeLogin(ctx, u, MethodPasskey)
	switch {
	case errors.Is(err, ErrInactive):
		writeError(w, http.StatusForbidden, "this account has been deactivated")
		return
	case errors.Is(err, ErrEmailUnverified):
		writeError(w, http.StatusForbidden, "verify your email address before signing in")
		return
	case errors.Is(err, ErrSSORequired):
		writeError(w, http.StatusForbidden, "your organization requires single sign-on")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f.svc.touchCredential(ctx, "passkey:"+base64.RawURLEncoding.EncodeToString(cred.ID))
	http.SetCookie(w, cookie)
	if f.svc.OnUserLogin != nil {
		f.svc.OnUserLogin(w, r, u, MethodPasskey)
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// discoverableUser treats the user handle as the account id.
func (f *passkeyFlow) discoverableUser(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(_, userHandle []byte) (webauthn.User, error) {
		u, err := f.svc.getUserByID(ctx, string(userHandle))
		if err != nil {
			return nil, err
		}
		return f.webUserFor(ctx, u)
	}
}
