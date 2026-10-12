package client

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/nokkud/internal/leaktest"
)

func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}
