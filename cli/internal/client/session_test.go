package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nokkuv1 "github.com/nokku-sh/nokku/gen/nokku/v1"
	"github.com/nokku-sh/nokku/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/cli/internal/paths"
	"github.com/nokku-sh/nokku/cli/internal/state"
)

type fakeAuth struct {
	nokkuv1connect.UnimplementedAuthServiceHandler

	logouts atomic.Int32
	err     error
}

func (f *fakeAuth) Logout(context.Context, *nokkuv1.LogoutRequest) (*nokkuv1.LogoutResponse, error) {
	f.logouts.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &nokkuv1.LogoutResponse{}, nil
}

// signedInClient has a valid session for sessionKey, nokku.pub holds testSSHKey.
func signedInClient(t *testing.T, auth *fakeAuth, sessionKey string) *Client {
	t.Helper()
	setTestDirs(t)
	require.NoError(t, os.WriteFile(paths.PubKeyFile(), []byte(testSSHKey+" x@nokku\n"), 0o600))
	mux := http.NewServeMux()
	server := connect.NewServer()
	nokkuv1connect.RegisterAuthServiceHandler(server, auth)
	connecthttp.Mount(mux, server)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := &Client{State: &state.State{
		APIURL:           srv.URL,
		SessionToken:     "sess-token",
		SessionExpiresAt: time.Now().Add(time.Hour),
		SessionKey:       sessionKey,
	}}
	c.auth = nokkuv1connect.NewAuthServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
	require.NoError(t, c.State.Save())
	return c
}

// The core certifies only the key a sign-in sent, so an older key's session must end.
func TestEnsureSessionEndsTheSessionOfAnOldKey(t *testing.T) {
	const oldKey = "ssh-ed25519 AAAAold x@nokku"
	for name, tc := range map[string]struct {
		sessionKey string
		coreErr    error
		logouts    int32
		token      string
	}{
		"an old key":                       {oldKey, nil, 1, ""},
		"an old key, the core down":        {oldKey, connect.NewError(connect.CodeUnavailable, "down"), 1, ""},
		"the same key":                     {testSSHKey + " x@nokku", nil, 0, "sess-token"},
		"a CI session, which names no key": {"", nil, 0, "sess-token"},
	} {
		t.Run(name, func(t *testing.T) {
			auth := &fakeAuth{err: tc.coreErr}
			c := signedInClient(t, auth, tc.sessionKey)

			err := c.ensureSession(t.Context(), false)
			assert.Equal(t, tc.token == "", err != nil, "only an ended session asks for a sign-in: %v", err)
			assert.Equal(t, tc.logouts, auth.logouts.Load(), "logouts")
			assert.Equal(t, tc.token, c.State.SessionToken)
			assert.Equal(t, tc.token, state.Load().SessionToken, "the session on disk")
		})
	}
}
