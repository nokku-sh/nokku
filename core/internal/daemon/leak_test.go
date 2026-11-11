package daemon

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/leaktest"
)

func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}
