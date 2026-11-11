//go:build integration

package iam_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/core/internal/actor"
	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// The docs name both lifetimes.
const webSessionTTL = 7 * 24 * time.Hour

// sessionEnds is when the one session of that kind ends.
func (e *testEnv) sessionEnds(t *testing.T, ws actor.Workspace, userID string, kind actor.Kind) time.Time {
	t.Helper()
	var ends []time.Time
	require.NoError(t, e.in(t, ws, func(q *db.Queries) error {
		rows, err := q.ListUserSessions(t.Context(), userID)
		for _, row := range rows {
			if row.Kind == string(kind) {
				require.NotNil(t, row.ExpiresAt, "a person's session never ends")
				ends = append(ends, *row.ExpiresAt)
			}
		}
		return err
	}))
	require.Len(t, ends, 1, "sessions of kind %s", kind)
	return ends[0]
}

// approveNK signs nk in for u, approved from a browser session that came in by method.
func approveNK(t *testing.T, e *testEnv, ws actor.Workspace, u *db.User, method iam.Method) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	grant := beginDevice(t, e, ws)
	r := httptest.NewRequest(http.MethodPost, "/auth/device/verify",
		strings.NewReader(url.Values{"user_code": {grant.UserCode}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := iam.ContextWithToken(as(r.Context(), ws, u), db.AccessToken{Method: string(method)})
	approved := httptest.NewRecorder()
	e.svc.Device.Verify(approved, r.WithContext(ctx))
	require.Equal(t, http.StatusOK, approved.Code, approved.Body.String())
	polled := pollDevice(t, e, ws, grant, key)
	require.Equal(t, http.StatusOK, polled.Code, polled.Body.String())
}

func TestMailLinkSessionLastsAWeek(t *testing.T) {
	mail := newMailbox()
	e := newTestEnvWith(t, mail.deps())
	o := e.org(t)
	ctx := anon(t.Context(), o.ws)

	e.svc.RequestMagicLink(ctx, o.owner.Email)
	_, _, err := e.svc.ConsumeMagicLink(ctx, linkToken(t, mail.link(t)))
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now().Add(webSessionTTL), e.sessionEnds(t, o.ws, o.owner.ID, actor.KindUser),
		time.Minute)
}

// A sign-in through the provider lasts as long as any other, in the browser and in nk.
func TestProviderSessionLifetimes(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	wantSSOSuccess(t, h.runOIDCFlow(t, svc, ""))
	u := e.userByEmail(t, h.org.ws, h.email)
	require.NotNil(t, u)

	assert.WithinDuration(t, time.Now().Add(webSessionTTL), e.sessionEnds(t, h.org.ws, u.ID, actor.KindUser),
		time.Minute)

	approveNK(t, e, h.org.ws, u, iam.MethodOIDC)
	assert.WithinDuration(t, time.Now().Add(deviceSessionTTL), e.sessionEnds(t, h.org.ws, u.ID, actor.KindCLI),
		time.Minute)
}

// Where single sign-on is required, nothing but a new sign-in asks the provider
// whether someone is still there. So every session ends after a day.
func TestRequiredSSOEndsSessionsAfterADay(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	e.setEnforceSSO(t, h.org.ws, true)
	wantSSOSuccess(t, h.runOIDCFlow(t, svc, ""))
	u := e.userByEmail(t, h.org.ws, h.email)
	require.NotNil(t, u)
	day := time.Now().Add(iam.SSOSessionTTL)

	assert.WithinDuration(t, day, e.sessionEnds(t, h.org.ws, u.ID, actor.KindUser), time.Minute, "in the browser")
	approveNK(t, e, h.org.ws, u, iam.MethodOIDC)
	assert.WithinDuration(t, day, e.sessionEnds(t, h.org.ws, u.ID, actor.KindCLI), time.Minute, "in nk")

	// The owner's way in when the provider breaks is no way around the rule.
	_, _, err := e.svc.IssueSignIn(anon(t.Context(), h.org.ws), h.org.owner,
		iam.TokenParams{Kind: actor.KindUser, Method: iam.MethodPasskey, TTL: webSessionTTL})
	require.NoError(t, err)
	assert.WithinDuration(t, day, e.sessionEnds(t, h.org.ws, h.org.owner.ID, actor.KindUser), time.Minute,
		"the owner's passkey")
}
