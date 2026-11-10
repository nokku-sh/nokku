// Package safe keeps a panic in one goroutine from ending the daemon. One nokkud serves every session on its host,
// so what a single connection or recording runs into must stay its own problem.
package safe

import (
	"log/slog"
	"runtime/debug"
)

// Func wraps fn for a go statement, a WaitGroup or a timer. A panic is logged and ends only that goroutine.
func Func(where string, fn func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("recovered panic", "where", where, "panic", r, "stack", string(debug.Stack()))
			}
		}()
		fn()
	}
}
