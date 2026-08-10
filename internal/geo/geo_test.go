package geo

import (
	"path/filepath"
	"testing"
)

func TestLookup_NilClient(t *testing.T) {
	// A service without a database (e.g. no token configured) must never
	// crash and returns the fallback location.
	svc := &Service{}
	if got := svc.Lookup("203.0.113.1"); got != "Unknown Location" {
		t.Errorf("Lookup() = %q, want Unknown Location", got)
	}
}

func TestNew_NoEnv(t *testing.T) {
	t.Setenv("IP2LOCATION_TOKEN", "")
	t.Setenv("IP2LOCATION_DB_PATH", filepath.Join(t.TempDir(), "ip2location.bin"))
	svc := New()
	if svc == nil {
		t.Fatal("New() = nil")
	}
	if svc.db.Load() != nil {
		t.Error("New() without a database file should not load a database")
	}
	if got := svc.Lookup("203.0.113.1"); got != "Unknown Location" {
		t.Errorf("Lookup() = %q, want Unknown Location", got)
	}
}
