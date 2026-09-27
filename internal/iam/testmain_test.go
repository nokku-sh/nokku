package iam

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/testdb"
)

// TestMain clears the boot-seeding environment so constructing a Service in
// a test never reaches for a real social provider or admin account. Without
// this, a developer's shell env (direnv) leaks into New and the fakes see
// writes they do not model.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"GOOGLE_CLIENT_ID",
		"GOOGLE_CLIENT_SECRET",
		"GITHUB_CLIENT_ID",
		"GITHUB_CLIENT_SECRET",
		"NOKKU_ADMIN_EMAIL",
		"NOKKU_ADMIN_PASSWORD",
		"NOKKU_ADMIN_NAME",
	} {
		os.Unsetenv(key)
	}
	testdb.Setup("iam")
	os.Exit(m.Run())
}
