package api

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/protos/gen/nokku/v1"
	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/iam"
)

// Whoever signs up with someone else's address must not get a working
// account when the owner of the inbox clicks the link.
func TestVerifyEmailNeedsSignupBrowser(t *testing.T) {
	cfg, srv := newTestAPI(t)
	email := uuid.New().String() + "@api.test"

	ctx, info := connect.NewClientContext(t.Context())
	_, err := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL).
		Register(ctx, &nokkuv1.RegisterRequest{Email: &email, Password: new(accountPassword)})
	require.NoError(t, err)
	signupCookie, _, _ := strings.Cut(info.ResponseHeader().Get("Set-Cookie"), ";")
	require.NotEmpty(t, signupCookie, "registering marks the browser")

	u, err := cfg.IAM.GetUserByEmail(t.Context(), email)
	require.NoError(t, err)
	token, err := cfg.IAM.IssueToken(t.Context(), u.ID, iam.TokenVerifyEmail, time.Hour)
	require.NoError(t, err)
	verify := func(cookie string) error {
		_, err := nokkuv1connect.NewAuthServiceClient(srv.Client(), srv.URL, header("Cookie", cookie)).
			VerifyEmail(t.Context(), &nokkuv1.VerifyEmailRequest{Token: &token})
		return err
	}
	verified := func() bool {
		u, err := cfg.IAM.GetUserByEmail(t.Context(), email)
		require.NoError(t, err)
		return u.EmailVerified
	}

	assert.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(verify("")),
		"the link must be refused in a browser that did not sign up")
	assert.False(t, verified(), "a refused link verifies nothing")

	require.NoError(t, verify(signupCookie), "the refused attempt must leave the link usable")
	assert.True(t, verified())
}
