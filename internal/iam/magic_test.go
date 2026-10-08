package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/actor"
	"github.com/nokku-sh/nokku/internal/db"
	emailverify "github.com/nokku-sh/nokku/internal/email"
)

// mailbox captures the links the service would mail.
type mailbox struct {
	links chan string
}

func (e *testEnv) mailbox() *mailbox {
	m := &mailbox{links: make(chan string, 8)}
	e.svc.sendMagicLink = func(_ context.Context, _, _, link, _ string) error {
		m.links <- link
		return nil
	}
	e.svc.sendSignupLink = func(_ context.Context, _, _, _, link, _ string) error {
		m.links <- link
		return nil
	}
	return m
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
	e := newTestEnv(t)
	mail := e.mailbox()
	a, b := e.org(t), e.org(t)
	ctx := anon(t.Context(), a.ws)

	require.NoError(t, e.svc.RequestMagicLink(ctx, " "+a.owner.Email))
	link := mail.link(t)
	assert.Contains(t, link, testBaseURL+loginVerifyURL, "the link points at the workspace host")
	token := linkToken(t, link)

	_, _, err := e.svc.ConsumeMagicLink(anon(t.Context(), b.ws), token)
	require.ErrorIs(t, err, ErrInvalidToken, "a link of workspace a signed in on workspace b")

	u, cookie, err := e.svc.ConsumeMagicLink(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, a.owner.ID, u.ID)
	assert.Equal(t, sessionCookieName, cookie.Name)
	assert.Equal(t, 1, e.sessions(t, a.ws, a.owner.ID))

	_, _, err = e.svc.ConsumeMagicLink(ctx, token)
	require.ErrorIs(t, err, ErrInvalidToken, "a spent link signed in again")

	require.NoError(t, e.svc.RequestMagicLink(ctx, "nobody@"+testDomain()))
	mail.empty(t, "an unknown address gets no mail")

	require.NoError(t, e.svc.RequestMagicLink(anon(t.Context(), b.ws), a.owner.Email))
	mail.empty(t, "an address of workspace a gets no mail from workspace b")
}

// The mail service holds back a second link inside its cooldown. A link
// nobody got must not stay valid.
func TestUnsentMagicLinkIsDropped(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	var link string
	e.svc.sendMagicLink = func(_ context.Context, _, _, l, _ string) error {
		link = l
		return emailverify.ErrCooldown
	}

	require.NoError(t, e.svc.RequestMagicLink(ctx, o.owner.Email))
	require.NotEmpty(t, link, "the mail service was not asked")
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, link))
	require.ErrorIs(t, err, ErrInvalidToken, "a link that was never mailed signed in")
}

func TestMagicLinkHonorsEnforcedSSO(t *testing.T) {
	e := newTestEnv(t)
	mail := e.mailbox()
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	e.setEnforceSSO(t, o.ws, true)

	require.NoError(t, e.svc.RequestMagicLink(ctx, o.owner.Email))
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, mail.link(t)))
	require.ErrorIs(t, err, ErrSSORequired)
	assert.Zero(t, e.sessions(t, o.ws, o.owner.ID))
}

func TestSignupLinkCreatesInvitedUser(t *testing.T) {
	e := newTestEnv(t)
	mail := e.mailbox()
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	invite := e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR, 1)
	email := "new@" + testDomain()

	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, o.owner.Email, "Dup"), ErrEmailTaken)
	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, "bogus", email, "New"), ErrInviteSpent)
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
	require.ErrorIs(t, err, ErrInviteSpent)
	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, "late@"+testDomain(), ""), ErrInviteSpent)
}

// The invite page must not say "check your email" for a mail that failed. On
// cooldown the earlier link is still out there, so that one stays a success.
func TestUnsentSignupLinkIsAnError(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	invite := e.invite(t, o.ws, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER, 0)
	var link string
	sendErr := errors.New("smtp send: 535 Authentication Failed")
	e.svc.sendSignupLink = func(_ context.Context, _, _, _, l, _ string) error {
		link = l
		return sendErr
	}

	require.ErrorIs(t, e.svc.RequestSignupLink(ctx, invite, "lost@"+testDomain(), ""), ErrMailNotSent)
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, link))
	require.ErrorIs(t, err, ErrInvalidToken, "a link that was never mailed created an account")

	sendErr = emailverify.ErrCooldown
	require.NoError(t, e.svc.RequestSignupLink(ctx, invite, "lost@"+testDomain(), ""))
}

func TestSeatCapStopsSignup(t *testing.T) {
	e := newTestEnv(t)
	mail := e.mailbox()
	e.svc.canJoin = func(_ context.Context, _ string, used int64) error {
		if used >= 1 {
			return errors.New("plan allows 1 seat")
		}
		return nil
	}
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
	require.ErrorIs(t, err, ErrSeatLimit)
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
	require.ErrorIs(t, err, ErrInvalidToken, "the earlier link is replaced")

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
			ID: id, UserID: o.owner.ID, Type: string(MethodPasskey), Subject: id, Data: []byte{},
		})
	}
	require.NoError(t, e.svc.DeleteCredential(ctx, "passkey:a"))
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:b"), ErrLastCredential)
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:a"), ErrNotFound)

	// With mail configured a sign-in link is a way in, so the last passkey may go.
	e.mailbox()
	require.NoError(t, e.svc.DeleteCredential(ctx, "passkey:b"))
	assert.Zero(t, e.passkeys(t, o.ws, o.owner.ID))

	other := e.user(t, o.ws, "other@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	e.putCredential(t, o.ws, db.UpsertCredentialParams{
		ID:      "passkey:c",
		UserID:  other.ID,
		Type:    string(MethodPasskey),
		Subject: "c",
		Data:    []byte{},
	})
	require.ErrorIs(t, e.svc.DeleteCredential(ctx, "passkey:c"), ErrNotFound, "deleted another user's passkey")
	_ = actor.KindUser
}
