package iam

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/cache"
	"github.com/nokku-sh/nokku/core/internal/db"
)

const (
	challengeTTL       = 5 * time.Minute
	ceremonyCookieName = "webauthn_session"
	// A relying party is built per workspace host and kept for a while.
	relyingPartyTTL     = time.Hour
	relyingPartyEntries = 10_000
)

type webUser struct {
	user  *db.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webUser) WebAuthnName() string                       { return u.user.Email }
func (u *webUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type passkeyFlow struct {
	svc   *Service
	rps   *cache.TTL[string, *webauthn.WebAuthn]
	state *sealed[webauthn.SessionData]
}

func newPasskeyFlow(svc *Service) *passkeyFlow {
	return &passkeyFlow{
		svc: svc,
		rps: cache.New[string, *webauthn.WebAuthn](relyingPartyEntries, relyingPartyTTL),
		state: &sealed[webauthn.SessionData]{
			svc: svc, cookie: ceremonyCookieName, use: "webauthn:session", ttl: challengeTTL,
		},
	}
}

// rp is the relying party of the workspace. Its id is the host, so a passkey never answers for another workspace.
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
	f.rps.Set(ws.ID, wa)
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

// savePasskey keeps the label on a refresh. The upsert never moves a credential id to another account.
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
	if err := f.svc.RequireRecentSignIn(ctx); err != nil {
		http.SetCookie(w, f.svc.ClearSessionCookie())
		writeError(w, http.StatusUnauthorized, "sign in again to add a passkey")
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
	f.svc.spendFlow(flowID)
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
	f.svc.spendFlow(flowID)
	f.svc.touchCredential(ctx, passkeyCredentialID(cred))
	f.signIn(w, r, wu.user)
}

func (f *passkeyFlow) signIn(w http.ResponseWriter, r *http.Request, u *db.User) {
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
