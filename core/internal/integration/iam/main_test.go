//go:build integration

package iam_test

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

// TestMain clears the boot environment so a developer's shell never seeds providers or an admin.
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
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}
