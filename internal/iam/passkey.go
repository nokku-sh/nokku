package iam

import (
	"cmp"
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

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/cache"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

const (
	challengeTTL       = 5 * time.Minute
	ceremonyCookieName = "webauthn_session"
	maxSignupEmail     = 254
	maxSignupName      = 256
	// A relying party is built per workspace host and kept for a while.
	relyingPartyTTL = time.Hour
)

// passkeySignupState reserves the account so the user row only exists once
// the ceremony verifies. ID is the user handle the authenticator binds to.
type passkeySignupState struct {
	Session  *webauthn.SessionData `json:"session"`
	ID       string                `json:"id"`
	Email    string                `json:"email"`
	Name     string                `json:"name"`
	Role     nokkuv1.WorkspaceRole `json:"role"`
	InviteID string                `json:"invite_id"`
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
	rps    *cache.Local[*webauthn.WebAuthn]
	state  *sealed[webauthn.SessionData]
	signup *sealed[passkeySignupState]
}

func newPasskeyFlow(svc *Service) *passkeyFlow {
	return &passkeyFlow{
		svc: svc,
		rps: cache.NewLocal[*webauthn.WebAuthn](relyingPartyTTL),
		state: &sealed[webauthn.SessionData]{
			svc: svc, cookie: ceremonyCookieName, use: "webauthn:session", ttl: challengeTTL,
		},
		signup: &sealed[passkeySignupState]{
			svc: svc, cookie: ceremonyCookieName, use: "webauthn:signup", ttl: challengeTTL,
		},
	}
}

// rp is the relying party of the request's workspace. Its id is the host,
// so a passkey made on one workspace never answers for another.
func (f *passkeyFlow) rp(ctx context.Context) (*webauthn.WebAuthn, error) {
	ws, ok := actor.WorkspaceFromContext(ctx)
	if !ok {
		return nil, db.ErrWorkspaceNotPinned
	}
	if wa, ok := f.rps.Get(ws.ID); ok {
		return wa, nil
	}
	u, err := url.Parse(ws.BaseURL)
	if err != nil {
		return nil, err
	}
	row, err := f.svc.conn.Tenant().GetWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cmp.Or(row.Name, "Nokku"),
		RPID:          u.Hostname(),
		RPOrigins:     []string{ws.BaseURL},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, err
	}
	f.rps.Put(ws.ID, wa)
	return wa, nil
}

func (f *passkeyFlow) clearedCeremonyCookie() *http.Cookie {
	return f.svc.newCookie(ceremonyCookieName, "", time.Unix(0, 0))
}

func (f *passkeyFlow) webUserFor(ctx context.Context, u *db.User) (*webUser, error) {
	creds, err := f.svc.conn.Tenant().ListCredentialsByType(ctx, &db.ListCredentialsByTypeParams{
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

func passkeyCredentialID(cred *webauthn.Credential) string {
	return "passkey:" + base64.RawURLEncoding.EncodeToString(cred.ID)
}

// savePasskey keeps the existing label on a refresh. The upsert never moves a
// credential id to another account.
func savePasskey(ctx context.Context, q *db.Queries, userID string, cred *webauthn.Credential) (string, error) {
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
		ID:      passkeyCredentialID(cred),
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
	wa, err := f.rp(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}
	creation, session, err := wa.BeginRegistration(wu)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	if _, err := f.state.put(w, *session); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	WriteJSON(w, http.StatusOK, creation)
}

func (f *passkeyFlow) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := f.rp(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	session, flowID, err := f.state.take(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	wu, ok := f.sessionUser(ctx, w)
	if !ok {
		return
	}
	cred, err := wa.FinishRegistration(wu, session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}
	var name string
	err = f.svc.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		name, err = savePasskey(ctx, q, wu.user.ID, cred)
		return err
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "this passkey cannot be registered")
		return
	}
	f.svc.spendFlow(ctx, flowID)
	f.svc.record(ctx, event{
		Action: actionCredentialAdded,
		Kind:   actor.KindUser,
		Method: MethodPasskey,
		UserID: wu.user.ID,
		Email:  wu.user.Email,
	})
	http.SetCookie(w, f.clearedCeremonyCookie())
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "name": name})
}

// BeginSignup starts the passkey ceremony of an invited person. The invite
// is spent when the ceremony finishes.
func (f *passkeyFlow) BeginSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := f.rp(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	invite, err := f.svc.LookupInvite(ctx, r.PostFormValue("invite"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired invitation")
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	if err := emailverify.Verify(ctx, email, f.svc.strict); err != nil {
		writeError(w, http.StatusBadRequest, "please enter a valid email address")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	// Both travel in the ceremony cookie.
	if len(email) > maxSignupEmail || len(name) > maxSignupName {
		writeError(w, http.StatusBadRequest, "name or email is too long")
		return
	}
	if _, err := f.svc.GetUserByEmail(ctx, email); err == nil {
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}

	st := passkeySignupState{
		ID: uuid.NewV7().String(), Email: email, Name: name, Role: deref(invite.Role), InviteID: invite.ID,
	}
	creation, session, err := wa.BeginRegistration(&webUser{user: &db.User{ID: st.ID, Email: email, Name: name}})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	st.Session = session
	if _, err := f.signup.put(w, st); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	WriteJSON(w, http.StatusOK, creation)
}

// FinishSignup creates the account, spends the invite and signs the browser in.
func (f *passkeyFlow) FinishSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := f.rp(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	st, flowID, err := f.signup.take(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	cred, err := wa.FinishRegistration(&webUser{user: &db.User{ID: st.ID, Email: st.Email}}, *st.Session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration verification failed")
		return
	}

	var u *db.User
	err = f.svc.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		u, err = f.svc.createUser(ctx, q, db.CreateUserWithIDParams{
			ID: st.ID, Email: st.Email, Name: st.Name, Role: st.Role,
		}, st.InviteID)
		if err != nil {
			return err
		}
		_, err = savePasskey(ctx, q, u.ID, cred)
		return err
	})
	switch {
	case errors.Is(err, ErrEmailTaken):
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	case errors.Is(err, ErrInviteSpent):
		writeError(w, http.StatusBadRequest, "invalid or expired invitation")
		return
	case errors.Is(err, ErrSeatLimit):
		writeError(w, http.StatusForbidden, "this workspace has no seats left")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f.svc.record(
		ctx,
		event{Action: actionUserCreated, Kind: actor.KindUser, Method: MethodPasskey, UserID: u.ID, Email: u.Email},
	)
	f.svc.spendFlow(ctx, flowID)
	http.SetCookie(w, f.clearedCeremonyCookie())
	f.signIn(w, r, u, cred)
}

func (f *passkeyFlow) BeginLogin(w http.ResponseWriter, r *http.Request) {
	wa, err := f.rp(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	if _, err := f.state.put(w, *session); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	WriteJSON(w, http.StatusOK, assertion)
}

func (f *passkeyFlow) FinishLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wa, err := f.rp(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	session, flowID, err := f.state.take(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid or expired ceremony")
		return
	}
	found, cred, err := wa.FinishPasskeyLogin(f.discoverableUser(ctx), session, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "login verification failed")
		return
	}
	wu, ok := found.(*webUser)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	err = f.svc.conn.TenantTx(ctx, func(q *db.Queries) (err error) {
		_, err = savePasskey(ctx, q, wu.user.ID, cred)
		return err
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, f.clearedCeremonyCookie())
	f.svc.spendFlow(ctx, flowID)
	f.svc.touchCredential(ctx, passkeyCredentialID(cred))
	f.signIn(w, r, wu.user, cred)
}

func (f *passkeyFlow) signIn(w http.ResponseWriter, r *http.Request, u *db.User, _ *webauthn.Credential) {
	ctx := r.Context()
	cookie, err := f.svc.completeLogin(ctx, u, MethodPasskey)
	switch {
	case errors.Is(err, ErrInactive):
		writeError(w, http.StatusForbidden, "this account has been deactivated")
		return
	case errors.Is(err, ErrSSORequired):
		writeError(w, http.StatusForbidden, "this workspace requires single sign-on")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	http.SetCookie(w, cookie)
	if c := f.svc.RememberDevice(ctx, r.Header, r.RemoteAddr, u); c != nil {
		http.SetCookie(w, c)
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// discoverableUser treats the user handle as the account id.
func (f *passkeyFlow) discoverableUser(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(_, userHandle []byte) (webauthn.User, error) {
		u, err := f.svc.getUser(ctx, string(userHandle))
		if err != nil {
			return nil, err
		}
		return f.webUserFor(ctx, u)
	}
}
