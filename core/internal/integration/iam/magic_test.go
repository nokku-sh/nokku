//go:build integration

package iam_test

import (
	"context"
	"errors"
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	emailverify "github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// mailbox captures the links the service would mail.
type mailbox struct {
	links chan string
}

func newMailbox() *mailbox {
	return &mailbox{links: make(chan string, 8)}
}

// deps are the mail functions of a service that delivers into m.
func (m *mailbox) deps() iam.Deps {
	return iam.Deps{
		SendMagicLink: func(_ context.Context, _, _, link, _ string) error {
			m.links <- link
			return nil
		},
		SendSignupLink: func(_ context.Context, _, _, _, link, _ string) error {
			m.links <- link
			return nil
		},
	}
}

func (m *mailbox) link(t *testing.T) string {
	t.Helper()
	select {
	case l := <-m.links:
		return l
	case <-time.After(time.Second):
		t.Fatal("no mail arrived")
		return ""
	}
}

func (m *mailbox) empty(t *testing.T, msg string) {
	t.Helper()
	select {
	case l := <-m.links:
		t.Fatalf("%s, but got %s", msg, l)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestMagicLinkSignIn(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	a, b := e.org(t), e.org(t)
	ctx := anon(t.Context(), a.ws)

	e.svc.RequestMagicLink(ctx, " "+a.owner.Email)
	link := mail.link(t)
	assert.Contains(t, link, testBaseURL+loginVerifyURL, "the link points at the workspace host")
	token := linkToken(t, link)

	_, _, err := e.svc.ConsumeMagicLink(anon(t.Context(), b.ws), token)
	require.ErrorIs(t, err, iam.ErrInvalidToken, "a link of workspace a signed in on workspace b")

	u, cookie, err := e.svc.ConsumeMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, a.owner.ID, u.ID)
	assert.Equal(t, sessionCookieName, cookie.Name)
	assert.Equal(t, 1, e.sessions(t, a.ws, a.owner.ID))

	_, _, err = e.svc.ConsumeMagicLink(ctx, token)
	require.ErrorIs(t, err, iam.ErrInvalidToken, "a spent link signed in again")

	e.svc.RequestMagicLink(ctx, "nobody@"+testDomain())
	mail.empty(t, "an unknown address gets no mail")

	e.svc.RequestMagicLink(anon(t.Context(), b.ws), a.owner.Email)
	mail.empty(t, "an address of workspace a gets no mail from workspace b")
}

// The mail service holds back a second link inside its cooldown. A link nobody got must not stay valid.
func TestUnsentMagicLinkIsDropped(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, iam.Deps{SendMagicLink: func(_ context.Context, _, _, l, _ string) error {
		mail.links <- l
		return emailverify.ErrCooldown
	}})
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)

	e.svc.RequestMagicLink(ctx, o.owner.Email)
	link := mail.link(t)
	// The mail goes out detached, so the drop lands a moment after the request.
	require.Eventually(t, func() bool {
		var n int
		err := e.conn.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM one_time_tokens WHERE user_id = $1", o.owner.ID).
			Scan(&n)
		return err == nil && n == 0
	}, 5*time.Second, 20*time.Millisecond, "the unsent link stayed")
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, link))
	require.ErrorIs(t, err, iam.ErrInvalidToken, "a link that was never mailed signed in")
}

func TestMagicLinkHonorsEnforcedSSO(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	member := e.user(t, o.ws, "member@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	e.setEnforceSSO(t, o.ws, true)

	e.svc.RequestMagicLink(ctx, member.Email)
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, mail.link(t)))
	require.ErrorIs(t, err, iam.ErrSSORequired)
	assert.Zero(t, e.sessions(t, o.ws, member.ID))

	// The owner keeps the link, or a broken provider locks the workspace for good.
	e.svc.RequestMagicLink(ctx, o.owner.Email)
	_, _, err = e.svc.ConsumeMagicLink(ctx, linkToken(t, mail.link(t)))
	require.NoError(t, err)
	assert.Equal(t, 1, e.sessions(t, o.ws, o.owner.ID))
}

func TestSignupLinkCreatesInvitedUser(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	invite := e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, 1)
	email := "new@" + testDomain()

	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, o.owner.Email, "Dup"), iam.ErrEmailTaken)
	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, "bogus", email, "New"), iam.ErrInviteSpent)
	require.NoError(t, e.svc.RequestSignupLink(ctx, invite, email, "New"))
	token := linkToken(t, mail.link(t))
	assert.Nil(t, e.userByEmail(t, o.ws, email), "the account exists before the link was used")

	u, cookie, err := e.svc.ConsumeMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, email, u.Email)
	assert.Equal(t, "New", u.Name)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, u.Role, "the role comes from the invite")
	assert.NotNil(t, cookie)
	assert.Equal(t, 1, e.sessions(t, o.ws, u.ID))

	// The one-use invite is spent now.
	_, err = e.svc.LookupInvite(ctx, invite)
	require.ErrorIs(t, err, iam.ErrInviteSpent)
	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, "late@"+testDomain(), ""), iam.ErrInviteSpent)
}

// The invite page must not say "check your email" for a mail that failed. On cooldown the earlier link still works.
func TestUnsentSignupLinkIsAnError(t *testing.T) {
	var link string
	sendErr := errors.New("smtp send: 535 Authentication Failed")
	e := newTestEnvWith(t, iam.Deps{SendSignupLink: func(_ context.Context, _, _, _, l, _ string) error {
		link = l
		return sendErr
	}})
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	invite := e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, 0)

	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, "lost@"+testDomain(), ""), iam.ErrMailNotSent)
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, link))
	require.ErrorIs(t, err, iam.ErrInvalidToken, "a link that was never mailed created an account")

	sendErr = emailverify.ErrCooldown
	require.NoError(t, e.svc.RequestSignupLink(ctx, invite, "lost@"+testDomain(), ""))
}

func TestSeatCapStopsSignup(t *testing.T) {
	mail := newMailbox()
	deps := mail.deps()
	deps.CanJoin = func(_ context.Context, _ string, used int64) error {
		if used >= 1 {
			return errors.New("plan allows 1 seat")
		}
		return nil
	}
	e := newTestEnvWith(t, deps)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)

	require.NoError(
		t,
		e.svc.RequestSignupLink(
			ctx,
			e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, 0),
			"two@"+testDomain(),
			"",
		),
	)
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, mail.link(t)))
	require.ErrorIs(t, err, iam.ErrSeatLimit)
	assert.Nil(t, e.userByEmail(t, o.ws, "two@"+testDomain()))
}

func TestBootstrapMakesTheOwnerOnce(t *testing.T) {
	e := newTestEnv(t)
	ws := e.workspace(t)
	email := "admin@" + testDomain()
	t.Setenv("NOKKU_ADMIN_EMAIL", email)
	t.Setenv("NOKKU_ADMIN_NAME", "Admin")

	first, err := e.svc.Bootstrap(t.Context(), ws)
	require.NoError(t, err)
	assert.Contains(t, first, "/login/verify?token=", "an owner without a passkey gets a link")
	owner := e.userByEmail(t, ws, email)
	require.NotNil(t, owner)
	assert.Equal(t, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_OWNER, owner.Role)

	// The second boot keeps the owner and only re-issues the link.
	t.Setenv("NOKKU_ADMIN_EMAIL", "other@"+testDomain())
	second, err := e.svc.Bootstrap(t.Context(), ws)
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "every boot issues a fresh link")
	assert.Nil(t, e.userByEmail(t, ws, "other@"+testDomain()), "a second admin was made")

	_, _, err = e.svc.ConsumeMagicLink(anon(t.Context(), ws), linkToken(t, first))
	require.ErrorIs(t, err, iam.ErrInvalidToken, "the earlier link is replaced")

	_, link, err := e.svc.AdminLink(t.Context(), ws)
	require.NoError(t, err)
	u, _, err := e.svc.ConsumeMagicLink(anon(t.Context(), ws), linkToken(t, link))
	require.NoError(t, err)
	assert.Equal(t, owner.ID, u.ID)
}

func TestLastCredentialStays(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := as(t.Context(), o.ws, o.owner)
	for _, id := range []string{"passkey:a", "passkey:b"} {
		e.putCredential(t, o.ws, db.UpsertCredentialParams{
			ID: id, UserID: o.owner.ID, Type: string(iam.MethodPasskey), Subject: id, Data: []byte{},
		})
	}
	require.NoError(t, e.svc.DeleteCredential(ctx, "passkey:a"))
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:b"), iam.ErrLastCredential)
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:a"), iam.ErrNotFound)

	// With mail configured a sign-in link is a way in, so the last passkey may go.
	e = newTestEnvWith(t, newMailbox().deps())
	require.NoError(t, e.svc.DeleteCredential(ctx, "passkey:b"))
	assert.Zero(t, e.passkeys(t, o.ws, o.owner.ID))

	other := e.user(t, o.ws, "other@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID:      "passkey:c",
		UserID:  other.ID,
		Type:    string(iam.MethodPasskey),
		Subject: "c",
		Data:    []byte{},
	})
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:c"), iam.ErrNotFound, "deleted another user's passkey")
	_ = actor.KindUser
}

// The environment names the issuer and the client. Whether the provider is on and who it lets in is the admin's.
func TestBootstrapKeepsWhatTheAdminSet(t *testing.T) {
	e := newTestEnv(t)
	ws := e.workspace(t)
	ctx := anon(t.Context(), ws)
	t.Setenv("MICROSOFT_CLIENT_ID", "client")
	t.Setenv("MICROSOFT_CLIENT_SECRET", "s3cret")
	t.Setenv("MICROSOFT_TENANT_ID", "tenant-a")

	_, err := e.svc.Bootstrap(t.Context(), ws)
	require.NoError(t, err)
	seeded, err := e.svc.GetSSOProvider(ctx, "microsoft")
	require.NoError(t, err)
	assert.True(t, seeded.Enabled && seeded.OIDC.JITProvisioning, "a fresh provider starts on")

	seeded.Enabled, seeded.OIDC.JITProvisioning = false, false
	_, err = e.svc.PutSSOProvider(ctx, *seeded)
	require.NoError(t, err)
	e.putCredential(t, ws, db.UpsertCredentialParams{
		ID: "ms-sub", UserID: e.user(t, ws, "dev@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER).ID,
		Type: string(iam.MethodOIDC), Provider: "microsoft", Subject: "sub", Data: []byte{},
	})

	_, err = e.svc.Bootstrap(t.Context(), ws)
	require.NoError(t, err)
	again, err := e.svc.GetSSOProvider(ctx, "microsoft")
	require.NoError(t, err)
	assert.False(t, again.Enabled, "the boot switched the provider back on")
	assert.False(t, again.OIDC.JITProvisioning, "the boot switched JIT back on")
	assert.NotNil(t, e.oidcCredential(t, ws, "microsoft", "sub"), "the same issuer dropped its identities")

	t.Setenv("MICROSOFT_TENANT_ID", "tenant-b")
	_, err = e.svc.Bootstrap(t.Context(), ws)
	require.NoError(t, err)
	moved, err := e.svc.GetSSOProvider(ctx, "microsoft")
	require.NoError(t, err)
	assert.Contains(t, moved.OIDC.IssuerURL, "tenant-b")
	assert.Nil(t, e.oidcCredential(t, ws, "microsoft", "sub"), "an identity of the old tenant survived")
}

// sub is only unique per issuer. The identities go in the same step as the issuer, or a failure in between keeps them.
func TestNewIssuerUnlinksIdentities(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	p := iam.SSOProvider{
		ProviderID: "corp", Name: "Corp", Enabled: true,
		OIDC: iam.OIDCProvider{IssuerURL: "https://old.example", ClientID: "nokku", ClientSecret: "s3cret"},
	}
	_, err := e.svc.PutSSOProvider(ctx, p)
	require.NoError(t, err)
	member := e.user(t, o.ws, "dev@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID:       "corp-sub",
		UserID:   member.ID,
		Type:     string(iam.MethodOIDC),
		Provider: "corp",
		Subject:  "sub",
		Data:     []byte{},
	})

	p.Name, p.OIDC.ClientSecret = "Corp SSO", ""
	_, err = e.svc.PutSSOProvider(ctx, p)
	require.NoError(t, err)
	require.NotNil(t, e.oidcCredential(t, o.ws, "corp", "sub"), "an edit of the same issuer unlinked")

	p.OIDC.IssuerURL = "https://new.example"
	_, err = e.svc.PutSSOProvider(ctx, p)
	require.ErrorIs(t, err, iam.ErrSecretRequired)
	require.NotNil(t, e.oidcCredential(t, o.ws, "corp", "sub"), "a refused change unlinked")

	p.OIDC.ClientSecret = "n3w"
	_, err = e.svc.PutSSOProvider(ctx, p)
	require.NoError(t, err)
	assert.Nil(t, e.oidcCredential(t, o.ws, "corp", "sub"), "an identity of the old issuer survived")
}
