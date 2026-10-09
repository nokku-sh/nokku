package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/protos/gen/nokku/v1/nokkuv1connect"

	"github.com/nokku-sh/nokku/internal/config"
)

func TestRateLimited(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/nokku.v1.UtilService/Whoami", true},
		{"/nokku.v1.AuthService/RequestMagicLink", true},
		{"/oidc/callback", true},
		{"/scim/v2/ws/Users", true},
		{"/passkey/login/begin", true},
		{"/auth/device", true},
		{"/avatars/user-1", true},
		{"/terminal/ws", true},
		{"/webhooks/stripe", true},
		{"/", true},
		{"/login", true},
		{"/totally/unknown", true},

		// A limit here would block legitimate reconnect storms.
		{"/nokku.v1.DaemonControlService/Connect", false},
		{"/nokku.v1.DaemonControlService/DaemonRelay", false},
		// Enrollment is public and takes a token, so it stays limited.
		{"/nokku.v1.DaemonControlService/EnrollDaemon", true},
		{"/nokku.v1.DaemonControlService/SyncDaemon", true},

		// One page load pulls many hashed assets.
		{"/_app/immutable/chunks/app.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := rateLimited(tt.path); got != tt.want {
				t.Errorf("rateLimited(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestWithRateLimit(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	h := s.withRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(path, addr string) int {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	const office, other = "203.0.113.7:4000", "203.0.113.8:4000"
	for i := range authPerMinute {
		require.Equal(t, http.StatusNoContent, call("/nokku.v1.AuthService/RequestMagicLink", office), "login %d", i+1)
	}
	assert.Equal(
		t,
		http.StatusTooManyRequests,
		call("/nokku.v1.AuthService/RequestMagicLink", office),
		"one past the auth limit",
	)
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.TargetService/ListTargets", office),
		"the rest of the API has its own budget")
	assert.Equal(
		t,
		http.StatusNoContent,
		call("/nokku.v1.AuthService/RequestMagicLink", other),
		"another address is not affected",
	)
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.DaemonControlService/Connect", office),
		"daemon streams are never limited")
}

// Anyone can start a device login, and every start parks a grant.
func TestWithRateLimitDeviceStart(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	h := s.withRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(path, addr string) int {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	const flood, other = "203.0.113.7:4000", "203.0.113.8:4000"
	for i := range deviceStartsPerWindow {
		require.Equal(t, http.StatusNoContent, call("/auth/device", flood), "start %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, call("/auth/device", flood), "one past the limit")
	assert.Equal(t, http.StatusNoContent, call("/auth/device", other), "another address still gets a grant")
	assert.Equal(t, http.StatusNoContent, call("/auth/device/token", flood),
		"a login that is already waiting keeps polling")
	assert.Equal(t, http.StatusNoContent, call("/auth/device/verify", flood), "and can still be approved")
}

// Anyone can sign up on the hosted service, and every signup makes a workspace and a mail.
func TestWithRateLimitSignup(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	h := s.withRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(path, addr string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	const signup = nokkuv1connect.WorkspaceServiceCreateWorkspaceProcedure
	const flood, other = "203.0.113.7:4000", "203.0.113.8:4000"
	for i := range signupsPerWindow {
		require.Equal(t, http.StatusNoContent, call(signup, flood).Code, "signup %d", i+1)
	}
	refused := call(signup, flood)
	assert.Equal(t, http.StatusTooManyRequests, refused.Code, "one past the limit")
	assert.Contains(t, refused.Body.String(), "resource_exhausted", "an RPC error, the form can show it")
	assert.Equal(t, http.StatusNoContent, call(signup, other).Code, "another address still signs up")
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.AuthService/RequestMagicLink", flood).Code,
		"signing in has a budget of its own")
}

func TestIsAuthRoute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Everything that mints or spends a link gets the strict limit.
		{"/nokku.v1.AuthService/RequestMagicLink", true},
		{"/nokku.v1.AuthService/ConsumeMagicLink", true},
		{"/nokku.v1.InvitationService/AcceptInvitation", true},
		{"/nokku.v1.WorkspaceService/CreateWorkspace", true},

		// Other RPCs stay on the general limit.
		{"/nokku.v1.AccountService/GetAccount", false},
		{"/nokku.v1.WorkspaceService/GetWorkspace", false},

		// The HTTP auth mounts keep the strict limit.
		{"/auth/device", true},
		{"/passkey/login/begin", true},
		{"/oidc/login", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAuthRoute(tt.path); got != tt.want {
				t.Errorf("isAuthRoute(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
