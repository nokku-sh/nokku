package geo

import (
	"testing"
)

func TestLookup_NilClient(t *testing.T) {
	// A service without a client (e.g. no token configured) must never
	// crash and returns the fallback location.
	svc := &Service{}
	if got := svc.Lookup("203.0.113.1"); got != "Unknown Location" {
		t.Errorf("Lookup() = %q, want Unknown Location", got)
	}
}

func TestNew_NoEnv(t *testing.T) {
	t.Setenv("IPLOCATE_API_KEY", "")
	svc := New()
	if svc == nil {
		t.Fatal("New() = nil")
	}
	if svc.client == nil {
		t.Error("New() should always create a client")
	}
}
