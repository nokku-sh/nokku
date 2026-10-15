//go:build integration

package iam_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"

	"github.com/nokku-sh/nokku/core/internal/db"
	"github.com/nokku-sh/nokku/core/internal/iam"
)

// testRequest is what the settings page's test button sends.
func testRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oidc/test?provider="+testProviderID, nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// testResult follows the redirect back to the settings page and reads the result as whoever ran the test.
func testResult(ctx context.Context, t *testing.T, svc *iam.Service, rec *httptest.ResponseRecorder) *nokkuv1.SSOTest {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/settings/sso", loc.Path, "a test goes back to the settings page, got %q", loc)
	res, err := svc.SSOTest(ctx, loc.Query().Get("test"))
	require.NoError(t, err)
	return res
}

// A test runs the whole flow and stops before anything changes, so it never makes the account it reports on.
func TestSSOTestChangesNothing(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	owner := as(t.Context(), h.org.ws, h.org.owner)
	h.user()

	f := h.startOIDCFlowFrom(t, svc, testRequest(owner))
	res := testResult(owner, t, svc, f.callback(t, svc, ""))

	assert.Nil(t, res.FailedStep, "error: %s", res.GetError())
	assert.Equal(t, nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_CREATES, res.GetOutcome())
	assert.Equal(t, oidcTestSubject, res.GetSubject())
	assert.Equal(t, h.email, res.GetEmail())
	assert.True(t, res.GetEmailVerified())
	assert.Contains(t, res.GetClaims(), "email")

	assert.Nil(t, e.userByEmail(t, h.org.ws, h.email), "a test provisioned the account")
	assert.Nil(t, e.oidcCredential(t, h.org.ws, testProviderID, oidcTestSubject), "a test linked the identity")
	assert.Zero(t, e.sessions(t, h.org.ws, h.org.owner.ID), "a test signed the owner in again")
}

// The result names who a real sign-in lands on, and the owner is never matched by email.
func TestSSOTestPreviewsTheMatch(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, false)
	owner := as(t.Context(), h.org.ws, h.org.owner)
	bob := e.user(t, h.org.ws, "bob@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	gone := e.user(t, h.org.ws, "gone@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_MEMBER)
	require.NoError(t, e.in(t, h.org.ws, func(q *db.Queries) error {
		return q.SetUserActive(t.Context(), &db.SetUserActiveParams{ID: gone.ID, Active: false})
	}))

	for _, tc := range []struct {
		email  string
		want   nokkuv1.SSOTestOutcome
		member string
	}{
		{"nobody@" + testDomain(), nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_NO_ACCOUNT, ""},
		{bob.Email, nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_SIGNS_IN, bob.Email},
		{gone.Email, nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_INACTIVE, gone.Email},
		{h.org.owner.Email, nokkuv1.SSOTestOutcome_SSO_TEST_OUTCOME_OWNER_LINK, h.org.owner.Email},
	} {
		h.email = tc.email
		h.user()
		f := h.startOIDCFlowFrom(t, svc, testRequest(owner))
		res := testResult(owner, t, svc, f.callback(t, svc, ""))
		assert.Equal(t, tc.want, res.GetOutcome(), "signing in as %s", tc.email)
		assert.Equal(t, tc.member, res.GetMemberEmail(), "signing in as %s", tc.email)
	}
}

// Each step that breaks is named, with the reason the sign-in page never shows.
func TestSSOTestNamesTheFailedStep(t *testing.T) {
	h := newOIDCIdP(t)
	_, svc := h.setup(t, true)
	owner := as(t.Context(), h.org.ws, h.org.owner)

	h.user()
	f := h.startOIDCFlowFrom(t, svc, testRequest(owner))
	res := testResult(owner, t, svc, f.callback(t, svc, "error=access_denied&error_description=Not+assigned"))
	assert.Equal(t, nokkuv1.SSOTestStep_SSO_TEST_STEP_AUTHORIZE, res.GetFailedStep())
	assert.Equal(t, "access_denied: Not assigned", res.GetError())

	h.user()
	h.mintBadToken(t, map[string]any{"aud": "someone-else"})
	f = h.startOIDCFlowFrom(t, svc, testRequest(owner))
	res = testResult(owner, t, svc, f.callback(t, svc, ""))
	assert.Equal(t, nokkuv1.SSOTestStep_SSO_TEST_STEP_ID_TOKEN, res.GetFailedStep())
	assert.NotEmpty(t, res.GetError())
}

// A provider gets checked before it shows up on the sign-in page.
func TestSSOTestRunsOnADisabledProvider(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	ctx := anon(t.Context(), h.org.ws)
	p, err := svc.GetSSOProvider(ctx, testProviderID)
	require.NoError(t, err)
	p.Enabled = false
	_, err = e.svc.PutSSOProvider(ctx, *p)
	require.NoError(t, err)

	owner := as(t.Context(), h.org.ws, h.org.owner)
	h.user()
	f := h.startOIDCFlowFrom(t, svc, testRequest(owner))
	res := testResult(owner, t, svc, f.callback(t, svc, ""))
	assert.Nil(t, res.FailedStep, "error: %s", res.GetError())
}

// A test shows what the provider says about whoever signs in, so only the owner starts one and reads it.
func TestSSOTestBelongsToTheOwner(t *testing.T) {
	h := newOIDCIdP(t)
	e, svc := h.setup(t, true)
	admin := e.user(t, h.org.ws, "admin@"+testDomain(), nokkuv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN)

	rec := httptest.NewRecorder()
	svc.OIDC.Test(rec, testRequest(as(t.Context(), h.org.ws, admin)))
	wantSSOFailure(t, rec)

	cross := testRequest(as(t.Context(), h.org.ws, h.org.owner))
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	rec = httptest.NewRecorder()
	svc.OIDC.Test(rec, cross)
	wantSSOFailure(t, rec)

	owner := as(t.Context(), h.org.ws, h.org.owner)
	h.user()
	f := h.startOIDCFlowFrom(t, svc, testRequest(owner))
	loc, err := url.Parse(f.callback(t, svc, "").Header().Get("Location"))
	require.NoError(t, err)
	_, err = svc.SSOTest(as(t.Context(), h.org.ws, admin), loc.Query().Get("test"))
	require.ErrorIs(t, err, iam.ErrNotFound, "another member read the owner's test")
}
