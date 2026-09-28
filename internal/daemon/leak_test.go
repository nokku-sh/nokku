package daemon

import (
	"bytes"
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/nokku-sh/nokku/internal/testdb"
)

// leaked skips detection when the toolchain has no goroutineleak profile.
func leaked() (string, bool) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return "", false
	}
	var b bytes.Buffer
	p.WriteTo(&b, 1)
	return b.String(), p.Count() > 0
}

// TestMain fails the suite on any provably stuck goroutine, the pool is the
// leak-prone code.
func TestMain(m *testing.M) {
	testdb.Setup("daemon")
	code := m.Run()
	if code == 0 {
		if report, ok := leaked(); ok {
			fmt.Fprintf(os.Stderr, "leaked goroutines:\n%s", report)
			code = 1
		}
	}
	os.Exit(code)
}
