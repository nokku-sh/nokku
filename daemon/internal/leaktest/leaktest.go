package leaktest

import (
	"bytes"
	"fmt"
	"os"
	"runtime/pprof"
)

// Exit returns 1 when goroutines leaked. Wire it to m.Run()'s result in TestMain, after teardown.
func Exit(code int) int {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return code
	}

	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		fmt.Fprintf(os.Stderr, "write goroutineleak profile: %v\n", err)
		return 1
	}
	if p.Count() > 0 {
		fmt.Fprintf(os.Stderr, "leaked goroutines:\n%s\n", buf.String())
		return 1
	}
	return code
}
