//go:build integration

package iam_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	emailverify "github.com/nokku-sh/nokku/core/internal/email"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

const (
	member = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER
	editor = nokkuv1.WorkspaceRole_WORKSPACE_ROLE_EDITOR
)

// An invite makes one account, with its address and role. Looking at it spends
// nothing, a mail scanner may open it.
func TestInviteCreatesOneAccount(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	a, b := e.org(t), e.org(t)
	ctx := anon(t.Context(), a.ws)
	domain := testDomain()
	email := "new@" + domain

	_, err := e.svc.Invite(ctx, a.owner.Email, editor)
	require.ErrorIs(t, err, iam.ErrEmailTaken)
	link, err := e.svc.Invite(ctx, " New@"+domain, editor)
	require.NoError(t, err)
	assert.Empty(t, link, "a mailed link came back to the admin")
	mailed := mail.link(t)
	assert.Contains(t, mailed, testBaseURL+inviteURL, "the link points at the workspace host")
	token := linkToken(t, mailed)

	for range 2 {
		inv, err := e.svc.LookupInvite(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, email, inv.Email)
		assert.Equal(t, editor, *inv.Role)
	}
	assert.Nil(t, e.userByEmail(t, a.ws, email), "looking at the invite made the account")

	_, _, err = e.svc.AcceptInvite(anon(t.Context(), b.ws), token, "New")
	require.ErrorIs(t, err, iam.ErrInviteSpent, "an invite of workspace a joined workspace b")

	u, cookie, err := e.svc.AcceptInvite(ctx, token, " New ")
	require.NoError(t, err)
	assert.Equal(t, email, u.Email)
	assert.Equal(t, "New", u.Name)
	assert.Equal(t, editor, u.Role, "the role comes from the invite")
	assert.Equal(t, sessionCookieName, cookie.Name)
	assert.Equal(t, 1, e.sessions(t, a.ws, u.ID))

	_, _, err = e.svc.AcceptInvite(ctx, token, "Again")
	require.ErrorIs(t, err, iam.ErrInviteSpent, "a spent invite made a second account")
	_, err = e.svc.LookupInvite(ctx, token)
	require.ErrorIs(t, err, iam.ErrInviteSpent)
}

// A new invite of an address replaces the link, so a resend with another role
// leaves no second way in.
func TestInviteReplacesTheEarlierLink(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	email := "new@" + testDomain()

	_, err := e.svc.Invite(ctx, email, editor)
	require.NoError(t, err)
	first := linkToken(t, mail.link(t))
	_, err = e.svc.Invite(ctx, email, member)
	require.NoError(t, err)
	second := linkToken(t, mail.link(t))

	_, _, err = e.svc.AcceptInvite(ctx, first, "New")
	require.ErrorIs(t, err, iam.ErrInviteSpent, "the replaced link still works")
	u, _, err := e.svc.AcceptInvite(ctx, second, "New")
	require.NoError(t, err)
	assert.Equal(t, member, u.Role)
}

// A resend whose mail fails, on cooldown too, keeps the earlier link alive and
// the new one dead.
func TestUnsentInviteKeepsTheEarlierOne(t *testing.T) {
	var link string
	var sendErr error
	e := newTestEnvWith(t, iam.Deps{SendInvite: func(_ context.Context, _, _, _, l string, _ time.Duration) error {
		link = l
		return sendErr
	}})
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	email := "new@" + testDomain()

	_, err := e.svc.Invite(ctx, email, member)
	require.NoError(t, err)
	first := linkToken(t, link)

	for _, cause := range []error{emailverify.ErrCooldown, errors.New("smtp send: 535 Authentication Failed")} {
		sendErr = cause
		_, err = e.svc.Invite(ctx, email, editor)
		require.ErrorIs(t, err, iam.ErrMailNotSent)
		require.ErrorIs(t, err, cause)
		_, err = e.svc.LookupInvite(ctx, linkToken(t, link))
		require.ErrorIs(t, err, iam.ErrInviteSpent, "a link that was never mailed works")
	}
	_, _, err = e.svc.AcceptInvite(ctx, first, "New")
	require.NoError(t, err, "the earlier invite died with the failed resend")
}

// Without mail the admin gets the link and hands it over.
func TestInviteWithoutMailReturnsTheLink(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)

	link, err := e.svc.Invite(ctx, "new@"+testDomain(), member)
	require.NoError(t, err)
	assert.Contains(t, link, testBaseURL+inviteURL)
	_, _, err = e.svc.AcceptInvite(ctx, linkToken(t, link), "New")
	require.NoError(t, err)
}

// The seat cap holds at both ends. A refused accept keeps the invite for later.
func TestSeatCapHoldsForInvites(t *testing.T) {
	deps := iam.Deps{CanJoin: func(_ context.Context, _ string, used int64) error {
		if used >= 2 {
			return errors.New("plan allows 2 seats")
		}
		return nil
	}}
	e := newTestEnvWith(t, deps)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)

	first, err := e.svc.Invite(ctx, "one@"+testDomain(), member)
	require.NoError(t, err)
	second, err := e.svc.Invite(ctx, "two@"+testDomain(), member)
	require.NoError(t, err)
	_, _, err = e.svc.AcceptInvite(ctx, linkToken(t, first), "One")
	require.NoError(t, err)

	_, err = e.svc.Invite(ctx, "three@"+testDomain(), member)
	require.ErrorIs(t, err, iam.ErrSeatLimit, "an invite for a seat that is not there")
	_, _, err = e.svc.AcceptInvite(ctx, linkToken(t, second), "Two")
	require.ErrorIs(t, err, iam.ErrSeatLimit)
	assert.Nil(t, e.userByEmail(t, o.ws, "two@"+testDomain()))
	_, err = e.svc.LookupInvite(ctx, linkToken(t, second))
	require.NoError(t, err, "the refused accept spent the invite")
}

// An invited account has no provider. Required SSO refuses it, the invite
// stays.
func TestEnforcedSSOKeepsTheInvite(t *testing.T) {
	e := newTestEnv(t)
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)
	email := "new@" + testDomain()

	link, err := e.svc.Invite(ctx, email, member)
	require.NoError(t, err)
	token := linkToken(t, link)
	e.setEnforceSSO(t, o.ws, true)

	_, err = e.svc.Invite(ctx, "late@"+testDomain(), member)
	require.ErrorIs(t, err, iam.ErrSSORequired)
	_, _, err = e.svc.AcceptInvite(ctx, token, "New")
	require.ErrorIs(t, err, iam.ErrSSORequired)
	assert.Nil(t, e.userByEmail(t, o.ws, email), "an account that cannot sign in was made")

	e.setEnforceSSO(t, o.ws, false)
	_, _, err = e.svc.AcceptInvite(ctx, token, "New")
	require.NoError(t, err, "the refused accept spent the invite")
}
