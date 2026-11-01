//go:build integration

package iam_test

import (
	"context"
	"testing"
	"time"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// A new way in is mailed, so a stolen session that adds one shows in the inbox.
func TestNewWaysInAreMailed(t *testing.T) {
	mailed := make(chan string, 4)
	h := newOIDCIdP(t)
	e, svc := h.setupWith(t, iam.OIDCProvider{}, iam.Deps{
		SendNewWayIn: func(_ context.Context, userID, _, _, what, _ string) error {
			mailed <- userID + " " + what
			return nil
		},
	})
	next := func() string {
		t.Helper()
		select {
		case got := <-mailed:
			return got
		case <-time.After(2 * time.Second):
			t.Fatal("no mail went out")
			return ""
		}
	}

	u := newPasskeyDevice().enroll(t, e, h.org.ws, "bob@"+testDomain())
	assert.Contains(t, next(), u.ID+" The passkey ")

	f := h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, u)))
	wantSSOSuccess(t, f.callback(t, svc, ""))
	assert.Equal(t, u.ID+" Your Test OIDC account", next())

	// Linking the same identity again adds no way in.
	f = h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, u)))
	wantSSOSuccess(t, f.callback(t, svc, ""))

	select {
	case got := <-mailed:
		assert.Fail(t, "one more mail than ways in", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// A provider linked by address at a first sign-in is a new way in like any
// other. A brand new account has nobody to warn.
func TestFirstSSOSignInMailsAnExistingAccount(t *testing.T) {
	mailed := make(chan string, 4)
	h := newOIDCIdP(t)
	e, svc := h.setupWith(t, iam.OIDCProvider{JITProvisioning: true}, iam.Deps{
		SendNewWayIn: func(_ context.Context, userID, _, _, what, _ string) error {
			mailed <- userID + " " + what
			return nil
		},
	})

	wantSSOSuccess(t, h.runOIDCFlow(t, svc, ""))
	select {
	case got := <-mailed:
		require.FailNow(t, "a new account was warned about itself", got)
	case <-time.After(100 * time.Millisecond):
	}
	created := e.userByEmail(t, h.org.ws, h.email)
	require.NotNil(t, created)
	require.NoError(t, e.conn.Sys().DeleteUser(t.Context(), created.ID))

	u := e.user(t, h.org.ws, h.email, nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	wantSSOSuccess(t, h.runOIDCFlow(t, svc, ""))
	select {
	case got := <-mailed:
		assert.Equal(t, u.ID+" Your Test OIDC account", got)
	case <-time.After(2 * time.Second):
		t.Fatal("a provider linked at a first sign-in sent no mail")
	}
}
