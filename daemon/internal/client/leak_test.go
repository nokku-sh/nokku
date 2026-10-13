package client

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/daemon/internal/leaktest"
)

func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}
