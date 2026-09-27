package db

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokku/internal/testdb"
)

func TestMain(m *testing.M) {
	testdb.Setup("db")
	os.Exit(m.Run())
}
