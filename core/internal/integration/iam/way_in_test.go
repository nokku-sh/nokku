//go:build integration

package iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nokku-sh/nokku/core/internal/iam"
)

// Every new way into an account mails it, so a stolen session that adds one shows up in the inbox.
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

	h.user()
	f := h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, u)))
	wantSSOSuccess(t, f.callback(t, svc, ""))
	assert.Equal(t, u.ID+" Your Test OIDC account", next())

	// Linking the same identity again adds no way in.
	h.user()
	f = h.startOIDCFlowFrom(t, svc, linkRequest(as(t.Context(), h.org.ws, u)))
	wantSSOSuccess(t, f.callback(t, svc, ""))

	select {
	case got := <-mailed:
		t.Errorf("one more mail than ways in: %s", got)
	case <-time.After(200 * time.Millisecond):
	}
}
