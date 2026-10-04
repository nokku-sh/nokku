package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nokku-sh/nokku/internal/config"
)

func TestRateLimited(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/nokku.v1.UtilService/Whoami", true},
		{"/nokku.v1.AuthService/Login", true},
		{"/oauth/login", true},
		{"/oidc/callback", true},
		{"/saml/acs", true},
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
		{"/nokku.v1.DaemonSessionService/Stream", false},

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
		require.Equal(t, http.StatusNoContent, call("/nokku.v1.AuthService/Login", office), "login %d", i+1)
	}
	assert.Equal(t, http.StatusTooManyRequests, call("/nokku.v1.AuthService/Login", office), "one past the auth limit")
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.TargetService/ListTargets", office),
		"the rest of the API has its own budget")
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.AuthService/Login", other), "another address is not affected")
	assert.Equal(t, http.StatusNoContent, call("/nokku.v1.DaemonControlService/Connect", office),
		"daemon streams are never limited")
}

func TestIsAuthRoute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// The pre-session AuthService gets the strict brute-force limit.
		{"/nokku.v1.AuthService/Login", true},
		{"/nokku.v1.AuthService/Register", true},
		{"/nokku.v1.AuthService/DiscoverSSO", true},

		// Other RPCs stay on the general limit.
		{"/nokku.v1.AccountService/GetAccount", false},

		// The legacy HTTP auth mounts keep the strict limit.
		{"/auth/device", true},
		{"/passkey/login/begin", true},
		{"/oidc/login", true},
		{"/saml/acs", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAuthRoute(tt.path); got != tt.want {
				t.Errorf("isAuthRoute(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
