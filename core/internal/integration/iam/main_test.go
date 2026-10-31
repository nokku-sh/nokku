//go:build integration

package iam_test

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/core/internal/integration/testenv"
)

func TestMain(m *testing.M) {
	stop := testenv.Postgres()
	code := m.Run()
	stop()
	os.Exit(code)
}
