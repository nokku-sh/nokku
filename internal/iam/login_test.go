package iam

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
)

const testPassword = "correct horse battery"

func (e *testEnv) withPassword(t *testing.T, u *db.User) {
	t.Helper()
	if err := e.svc.Password.Store(t.Context(), u.ID, testPassword); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordLoginRequiresVerifiedEmail(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), false)
	e.withPassword(t, u)

	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, testPassword); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("unverified login err = %v, want ErrEmailUnverified", err)
	}
	if err := e.svc.VerifyUserEmail(t.Context(), u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, testPassword); err != nil {
		t.Fatalf("verified login: %v", err)
	}
	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, "wrong"); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
}

func TestBackupCodeLoginGatesBeforeSpendingCode(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), false)
	codes, err := e.svc.RotateBackupCodes(as(t.Context(), u.ID))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.svc.LoginWithBackupCode(t.Context(), u.Email, codes[0]); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("err = %v, want ErrEmailUnverified", err)
	}
	if err := e.svc.VerifyUserEmail(t.Context(), u.ID); err != nil {
		t.Fatal(err)
	}
	// The refused attempt left the code unspent.
	if _, _, err := e.svc.LoginWithBackupCode(t.Context(), u.Email, codes[0]); err != nil {
		t.Fatalf("login with the code: %v", err)
	}
	if _, _, err := e.svc.LoginWithBackupCode(t.Context(), u.Email, codes[0]); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("second use err = %v, want errInvalidCredentials", err)
	}
}

// Enforced SSO covers every non-SSO way in, not just passwords.
func TestSSOEnforcementCoversEveryMethod(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	e.provider(t, o, SSOProvider{
		Method: MethodOIDC,
		OIDC:   &OIDCProvider{IssuerURL: "https://idp.example", ClientID: "c", EnforceSSO: true},
	})
	u := e.user(t, "dev@"+o.domain, true)
	e.withPassword(t, u)
	codes, err := e.svc.RotateBackupCodes(as(t.Context(), u.ID))
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, testPassword); !errors.Is(err, ErrSSORequired) {
		t.Errorf("password: err = %v, want ErrSSORequired", err)
	}
	if _, _, err := e.svc.LoginWithBackupCode(t.Context(), u.Email, codes[0]); !errors.Is(err, ErrSSORequired) {
		t.Errorf("backup code: err = %v, want ErrSSORequired", err)
	}
	if _, err := e.svc.completeLogin(t.Context(), u, MethodPasskey); !errors.Is(err, ErrSSORequired) {
		t.Errorf("passkey: err = %v, want ErrSSORequired", err)
	}
	social := &linker{svc: e.svc, credType: MethodOAuth2}
	if _, err := social.Resolve(t.Context(), flowLinkOptions{
		ProviderID: "github", Subject: "gh-" + u.ID, Email: u.Email, EmailVerified: true,
	}); !errors.Is(err, ErrSSORequired) {
		t.Errorf("social login: err = %v, want ErrSSORequired", err)
	}
	if _, err := e.svc.completeLogin(t.Context(), u, MethodOIDC); err != nil {
		t.Errorf("sso login refused: %v", err)
	}
	if n := e.sessions(t, u.ID); n != 1 {
		t.Errorf("sessions = %d, want only the SSO one", n)
	}
}

func TestLinkerPolicy(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	enterprise := &linker{svc: e.svc, credType: MethodOIDC}
	social := &linker{svc: e.svc, credType: MethodOAuth2}
	outsider := e.user(t, "someone@"+testDomain(), true)

	cases := []struct {
		name string
		l    *linker
		opts flowLinkOptions
		ok   bool
	}{
		{"enterprise matches its domain", enterprise, flowLinkOptions{
			WorkspaceID: o.ws, Email: o.owner.Email,
		}, true},
		{"enterprise cannot claim a foreign account", enterprise, flowLinkOptions{
			WorkspaceID: o.ws, Email: outsider.Email, EmailVerified: true,
		}, false},
		{"enterprise cannot provision a foreign email", enterprise, flowLinkOptions{
			WorkspaceID: o.ws, Email: "new@" + testDomain(), EmailVerified: true, JITProvisioning: true,
		}, false},
		{"enterprise cannot link a signed-in foreign account", enterprise, flowLinkOptions{
			WorkspaceID: o.ws, LinkUserID: outsider.ID,
		}, false},
		{"social needs a verified email", social, flowLinkOptions{
			Email: outsider.Email,
		}, false},
		{"social with a verified email matches", social, flowLinkOptions{
			Email: outsider.Email, EmailVerified: true,
		}, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.ProviderID = o.ws
			if tc.l == social {
				tc.opts.ProviderID = "github"
			}
			tc.opts.Subject = "sub-" + time.Now().Format(time.RFC3339Nano) + string(rune('a'+i))
			_, err := tc.l.Resolve(t.Context(), tc.opts)
			if tc.ok && err != nil {
				t.Fatalf("want success, got %v", err)
			}
			if !tc.ok && !errors.Is(err, errIdentityRejected) {
				t.Fatalf("err = %v, want errIdentityRejected", err)
			}
		})
	}
	if e.isMember(t, o.ws, outsider.ID) {
		t.Error("a rejected identity joined the workspace")
	}
}

// A credential id belongs to one account for good. A client-chosen passkey
// id colliding with someone else's must not take it over.
func TestCredentialNeverMovesAccounts(t *testing.T) {
	e := newTestEnv(t)
	victim := e.user(t, "victim@"+testDomain(), true)
	attacker := e.user(t, "attacker@"+testDomain(), true)
	cred := &webauthn.Credential{ID: []byte("shared-credential-id-" + victim.ID), PublicKey: []byte("victim-key")}
	if _, err := savePasskey(t.Context(), e.conn.Sys(), victim.ID, cred); err != nil {
		t.Fatal(err)
	}

	stolen := &webauthn.Credential{ID: cred.ID, PublicKey: []byte("attacker-key")}
	if _, err := savePasskey(t.Context(), e.conn.Sys(), attacker.ID, stolen); err == nil {
		t.Fatal("a colliding passkey was saved for the attacker")
	}
	got, err := e.conn.Sys().GetCredential(t.Context(), &db.GetCredentialParams{
		UserID: victim.ID,
		ID:     "passkey:" + base64.RawURLEncoding.EncodeToString(cred.ID),
	})
	if err != nil {
		t.Fatalf("victim lost the credential: %v", err)
	}
	var stored webauthn.Credential
	if err := json.Unmarshal(got.Data, &stored); err != nil || string(stored.PublicKey) != "victim-key" {
		t.Error("victim's key material was replaced")
	}
}

// The browser middleware only trusts user cookie sessions. A CLI or daemon
// token sent as a header skips its DPoP binding there, so it is ignored.
func TestMiddlewareOnlyTrustsCookieSessions(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), true)
	_, cliToken, err := e.svc.IssueSession(t.Context(), SessionParams{
		SubjectID: u.ID, Kind: actor.KindCLI, Method: MethodDevice, Binding: "jkt", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, userToken, err := e.svc.IssueSession(t.Context(), SessionParams{
		SubjectID: u.ID, Kind: actor.KindUser, Method: MethodPassword, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	principal := func(r *http.Request) (actor.Principal, bool) {
		var p actor.Principal
		var ok bool
		e.svc.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			p, ok = actor.PrincipalFromContext(r.Context())
		})).ServeHTTP(httptest.NewRecorder(), r)
		return p, ok
	}

	bearer := httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	bearer.Header.Set("Authorization", "Bearer "+cliToken)
	if _, ok := principal(bearer); ok {
		t.Error("a header token authenticated on the browser surface")
	}
	cookie := httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	cookie.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cliToken})
	if _, ok := principal(cookie); ok {
		t.Error("a CLI token in the session cookie authenticated")
	}
	cookie = httptest.NewRequest(http.MethodGet, "/terminal/ws", nil)
	cookie.AddCookie(&http.Cookie{Name: sessionCookieName, Value: userToken})
	if p, ok := principal(cookie); !ok || p.ID != u.ID {
		t.Error("the user cookie session did not authenticate")
	}
}

func TestDeleteOwnSessionOnly(t *testing.T) {
	e := newTestEnv(t)
	alice := e.user(t, "alice@"+testDomain(), true)
	bob := e.user(t, "bob@"+testDomain(), true)
	sess, _, err := e.svc.IssueSession(
		t.Context(),
		SessionParams{SubjectID: bob.ID, Kind: actor.KindUser, Method: MethodPassword},
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = e.svc.DeleteOwnSession(as(t.Context(), alice.ID), SessionHash(sess.TokenHash))
	if n := e.sessions(t, bob.ID); n != 1 {
		t.Fatal("alice deleted bob's session")
	}
	if err := e.svc.DeleteOwnSession(as(t.Context(), bob.ID), SessionHash(sess.TokenHash)); err != nil {
		t.Fatal(err)
	}
	if n := e.sessions(t, bob.ID); n != 0 {
		t.Fatal("bob could not delete his own session")
	}
}

func TestConsumeTokenChecksPurpose(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), false)
	raw, err := e.svc.IssueToken(t.Context(), u.ID, TokenVerifyEmail, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ConsumeToken(t.Context(), raw, TokenPasswordReset); !errors.Is(err, errInvalidToken) {
		t.Fatalf("wrong purpose err = %v", err)
	}
	// The wrong-purpose attempt left the token usable.
	if id, err := e.svc.ConsumeToken(t.Context(), raw, TokenVerifyEmail); err != nil || id != u.ID {
		t.Fatalf("consume = %q, %v", id, err)
	}
	if _, err := e.svc.ConsumeToken(t.Context(), raw, TokenVerifyEmail); !errors.Is(err, errInvalidToken) {
		t.Fatal("a token was spent twice")
	}
}

func TestHasRecentToken(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), false)
	other := e.user(t, "other@"+testDomain(), false)
	if _, err := e.svc.IssueToken(t.Context(), u.ID, TokenVerifyEmail, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, userID, purpose string
		want                  bool
	}{
		{"same user and purpose", u.ID, TokenVerifyEmail, true},
		{"other user", other.ID, TokenVerifyEmail, false},
		{"other purpose", u.ID, TokenPasswordReset, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.svc.HasRecentToken(t.Context(), tc.userID, tc.purpose)
			if err != nil || got != tc.want {
				t.Errorf("HasRecentToken = %v, %v, want %v", got, err, tc.want)
			}
		})
	}
}

func TestDeleteUserOwnership(t *testing.T) {
	e := newTestEnv(t)
	owner := e.user(t, "owner@"+testDomain(), true)
	solo := e.workspace(t, owner.ID)
	shared := e.workspace(t, owner.ID)
	e.member(t, shared, e.user(t, "teammate@"+testDomain(), true).ID)

	err := e.svc.DeleteUser(as(t.Context(), owner.ID))
	if sw, ok := errors.AsType[*SharedWorkspacesError](err); !ok || len(sw.Names) != 1 {
		t.Fatalf("err = %v, want a SharedWorkspacesError naming one workspace", err)
	}
	if e.userByEmail(t, owner.Email) == nil {
		t.Fatal("account deleted while it owned a shared workspace")
	}

	if err := e.conn.Sys().DeleteWorkspace(t.Context(), shared); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteUser(as(t.Context(), owner.ID)); err != nil {
		t.Fatalf("delete with only a solo workspace: %v", err)
	}
	if _, err := e.conn.Sys().GetWorkspace(t.Context(), solo); err == nil {
		t.Error("the solo workspace survived its owner")
	}
}

// nk logout revokes its DPoP-bound session, but only with a valid proof: a
// leaked token alone cannot end someone's session.
func TestLogoutRevokesBoundSession(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "cli@"+testDomain(), true)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := e.svc.IssueSession(t.Context(), SessionParams{
		SubjectID: u.ID, Kind: actor.KindCLI, Method: MethodDevice,
		Binding: base64.RawURLEncoding.EncodeToString(tp), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	const procedure = "/nokku.v1.AuthService/Logout"
	header := http.Header{}
	header.Set("Authorization", "DPoP "+token)

	if err := e.svc.Logout(t.Context(), header, procedure); !errors.Is(err, ErrDPoPRequired) {
		t.Fatalf("logout without proof: err = %v, want ErrDPoPRequired", err)
	}
	if e.sessions(t, u.ID) != 1 {
		t.Fatal("a token without its proof ended the session")
	}

	header.Set(
		"DPoP",
		signProof(
			t,
			key,
			testBaseURL+procedure,
			DPoPATH(token),
			e.svc.DPoP.CurrentNonce(),
			time.Now(),
		),
	)
	if err := e.svc.Logout(t.Context(), header, procedure); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if n := e.sessions(t, u.ID); n != 0 {
		t.Fatalf("sessions after logout = %d, want 0", n)
	}
	// A second logout with the dead token still succeeds.
	header.Set(
		"DPoP",
		signProof(
			t,
			key,
			testBaseURL+procedure,
			DPoPATH(token),
			e.svc.DPoP.CurrentNonce(),
			time.Now(),
		),
	)
	if err := e.svc.Logout(t.Context(), header, procedure); err != nil {
		t.Fatalf("repeat logout: %v", err)
	}
}

func TestSessionRecordsDevice(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "device@"+testDomain(), true)
	header := http.Header{"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}}
	ctx := ContextWithRequestMeta(t.Context(), RequestMeta{Header: header, RemoteAddr: "203.0.113.7:4242"})

	sess, _, err := e.svc.IssueSession(ctx, SessionParams{
		SubjectID: u.ID, Kind: actor.KindUser, Method: MethodPassword, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserAgent != header.Get("User-Agent") {
		t.Errorf("user agent = %q, want the request's", sess.UserAgent)
	}
	if sess.Ip != "203.0.113.7" {
		t.Errorf("ip = %q, want 203.0.113.7", sess.Ip)
	}
}

func TestPasswordLoginMarksCredentialUsed(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "used@"+testDomain(), true)
	e.withPassword(t, u)
	stored := func() *db.Credential {
		t.Helper()
		c, err := e.svc.sys.GetCredential(t.Context(), &db.GetCredentialParams{
			UserID: u.ID, ID: passwordCredentialID(u.ID),
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, "wrong"); err == nil {
		t.Fatal("wrong password signed in")
	}
	if stored().LastUsedAt != nil {
		t.Error("a failed sign-in marked the password used")
	}
	if _, _, err := e.svc.Password.Login(t.Context(), u.Email, testPassword); err != nil {
		t.Fatalf("login: %v", err)
	}
	if stored().LastUsedAt == nil {
		t.Error("a successful sign-in did not mark the password used")
	}
}

func TestEmailChange(t *testing.T) {
	e := newTestEnv(t)
	ctx := t.Context()
	oldEmail, newEmail := "old@"+testDomain(), "new@"+testDomain()
	u := e.user(t, oldEmail, true)
	taken := e.user(t, "taken@"+testDomain(), true)

	if _, _, err := e.svc.RequestEmailChange(ctx, u, oldEmail); !errors.Is(err, ErrSameEmail) {
		t.Fatalf("same address err = %v, want ErrSameEmail", err)
	}
	if _, _, err := e.svc.RequestEmailChange(ctx, u, taken.Email); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("taken address err = %v, want ErrEmailTaken", err)
	}

	// A second request replaces the first, its link confirms nothing.
	stale, _, err := e.svc.RequestEmailChange(ctx, u, "typo@"+testDomain())
	if err != nil {
		t.Fatal(err)
	}
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, " "+strings.ToUpper(newEmail))
	if err != nil {
		t.Fatal(err)
	}
	if err = e.svc.ConfirmEmailChange(ctx, stale); !errors.Is(err, errInvalidToken) {
		t.Fatalf("stale link err = %v, want errInvalidToken", err)
	}
	if got := e.svc.PendingEmail(ctx, u.ID); got != newEmail {
		t.Fatalf("pending = %q, want %q", got, newEmail)
	}
	if got := e.userByEmail(t, oldEmail); got == nil {
		t.Fatal("the address changed before the new one was confirmed")
	}
	// The cancel link is not a confirm link.
	if err = e.svc.ConfirmEmailChange(ctx, cancel); !errors.Is(err, errInvalidToken) {
		t.Fatalf("cancel token as confirm err = %v, want errInvalidToken", err)
	}

	reset, err := e.svc.IssueToken(ctx, u.ID, TokenPasswordReset, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.svc.ConfirmEmailChange(ctx, confirm); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := e.userByEmail(t, newEmail); got == nil || got.ID != u.ID || !got.EmailVerified {
		t.Fatalf("after confirm the new address resolves to %+v", got)
	}
	if got := e.svc.PendingEmail(ctx, u.ID); got != "" {
		t.Fatalf("pending after confirm = %q", got)
	}
	if err = e.svc.ConfirmEmailChange(ctx, confirm); !errors.Is(err, errInvalidToken) {
		t.Fatalf("second confirm err = %v, want errInvalidToken", err)
	}
	if _, err = e.svc.ConsumeToken(ctx, reset, TokenPasswordReset); !errors.Is(err, errInvalidToken) {
		t.Fatalf("reset link for the old address survived: %v", err)
	}

	// The old inbox undoes the change and signs everyone out.
	_, session, err := e.svc.IssueSession(
		ctx,
		SessionParams{SubjectID: u.ID, Kind: actor.KindUser, Method: MethodPassword},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.svc.CancelEmailChange(ctx, cancel); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got := e.userByEmail(t, oldEmail); got == nil || got.ID != u.ID {
		t.Fatalf("after revert the old address resolves to %+v", got)
	}
	if _, err = e.svc.verifySession(ctx, session); err == nil {
		t.Fatal("a session survived the revert")
	}
	if err = e.svc.CancelEmailChange(ctx, cancel); !errors.Is(err, errInvalidToken) {
		t.Fatalf("second revert err = %v, want errInvalidToken", err)
	}
}

func TestEmailChangeCancelBeforeConfirm(t *testing.T) {
	e := newTestEnv(t)
	ctx := t.Context()
	u := e.user(t, "old@"+testDomain(), true)
	confirm, cancel, err := e.svc.RequestEmailChange(ctx, u, "new@"+testDomain())
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := e.svc.IssueSession(
		ctx,
		SessionParams{SubjectID: u.ID, Kind: actor.KindUser, Method: MethodPassword},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err = e.svc.CancelEmailChange(ctx, cancel); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err = e.svc.ConfirmEmailChange(ctx, confirm); !errors.Is(err, errInvalidToken) {
		t.Fatalf("confirm after cancel err = %v, want errInvalidToken", err)
	}
	if got := e.userByEmail(t, u.Email); got == nil {
		t.Fatal("cancel changed the address")
	}
	// Nothing changed yet, so nobody is signed out.
	if _, err = e.svc.verifySession(ctx, session); err != nil {
		t.Fatalf("cancel of a pending change ended the session: %v", err)
	}
}

// A device marker only names a known browser. It must never sign in, not even
// when it arrives in the session cookie.
func TestDeviceCookieIsNotASession(t *testing.T) {
	e := newTestEnv(t)
	u := e.user(t, "user@"+testDomain(), true)

	device := e.svc.RememberDevice(t.Context(), http.Header{}, "198.51.100.1:1234", u)
	if device == nil {
		t.Fatal("no device cookie issued")
	}
	header := http.Header{}
	header.Add("Cookie", sessionCookieName+"="+device.Value)
	if _, _, err := e.svc.Authenticate(t.Context(), header, "/nokku.v1.UtilService/Whoami"); err == nil {
		t.Fatal("device cookie authenticated as a session")
	}
}
