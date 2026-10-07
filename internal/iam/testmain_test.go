package iam

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/testdb"
)

// TestMain clears the boot environment so a developer's shell (direnv) never
// seeds providers or an admin into a test workspace.
func TestMain(m *testing.M) {
	for _, key := range []string{
		"GOOGLE_CLIENT_ID",
		"GOOGLE_CLIENT_SECRET",
		"MICROSOFT_CLIENT_ID",
		"MICROSOFT_CLIENT_SECRET",
		"MICROSOFT_TENANT_ID",
		"NOKKU_ADMIN_EMAIL",
		"NOKKU_ADMIN_NAME",
	} {
		os.Unsetenv(key)
	}
	testdb.Setup("iam")
	os.Exit(m.Run())
}
