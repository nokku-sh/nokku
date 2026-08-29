package daemon

import (
	"bytes"
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
)

// leaked returns the goroutineleak profile report and whether any goroutines
// are provably stuck. The profile only exists when the toolchain is built
// Without it, detection is skipped.
func leaked() (string, bool) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return "", false
	}
	var b bytes.Buffer
	p.WriteTo(&b, 1)
	return b.String(), p.Count() > 0
}

// TestMain fails the suite if any goroutine is left provably stuck after the
// tests finish. The daemon pool is the leak-prone code (channels, bidi
// streams, event subscribers), so guard it here rather than only in
// individual tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if report, ok := leaked(); ok {
			fmt.Fprintf(os.Stderr, "leaked goroutines:\n%s", report)
			code = 1
		}
	}
	os.Exit(code)
}
