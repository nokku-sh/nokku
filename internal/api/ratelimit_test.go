package api

import (
	"testing"
)

func TestIsAPIRoute(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// API routes are rate limited.
		{"/nokku.v1.UserService/Whoami", true},
		{"/nokku.v1.WorkspaceService/ListWorkspaces", true},
		{"/grpc.health.v1.Health/Check", true},
		{"/oauth/authorize", true},
		{"/saml/acs", true},
		{"/passkey/register", true},
		{"/avatars/user/1", true},
		{"/upload/thing", true},
		{"/terminal/foo", true},
		{"/stripe/webhook", true},
		{"/healthz", true},
		{"/debug/pprof", true},
		{"/v1/something", true},

		// Streaming daemon endpoints skip rate limiting (reconnect storms).
		{"/nokku.v1.DaemonControlService/Connect", false},
		{"/nokku.v1.DaemonSessionService/Stream", false},

		// Static assets and unknown paths are not rate limited.
		{"/", false},
		{"/static/app.js", false},
		{"/assets/logo.svg", false},
		{"/favicon.ico", false},
		{"/totally/unknown", false},
		{"/nokku.v2.Foo/Bar", false},
		{"/nokku.", false},
		{"/grpcx", false},
		{"/v2/x", false},
		{"/stripex", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAPIRoute(tt.path); got != tt.want {
				t.Errorf("isAPIRoute(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestRateLimiterStore_AllowsUpToBurst(t *testing.T) {
	store := newRateLimiterStore(1, 3) // 1 rps, burst 3

	for i := range 3 {
		if !store.allow("client-a") {
			t.Fatalf("request %d: want allowed within burst", i+1)
		}
	}
	if store.allow("client-a") {
		t.Error("request beyond burst: want denied")
	}
}

func TestRateLimiterStore_IndependentKeys(t *testing.T) {
	store := newRateLimiterStore(1, 2)

	store.allow("client-a")
	store.allow("client-a")
	if store.allow("client-a") {
		t.Error("client-a exhausted: want denied")
	}
	if !store.allow("client-b") {
		t.Error("client-b: want allowed (independent bucket)")
	}
	if !store.allow("client-b") {
		t.Error("client-b second request: want allowed")
	}
}

func TestRateLimiterStore_Refills(t *testing.T) {
	store := newRateLimiterStore(100, 1) // fast refill

	if !store.allow("k") {
		t.Fatal("first request: want allowed")
	}
	if store.allow("k") {
		t.Fatal("second request: want denied (burst 1)")
	}
}
