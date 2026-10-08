//go:build integration

package daemon_test

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/integration/testenv"
)

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}
