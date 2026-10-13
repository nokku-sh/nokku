package api

import (
	"net/http"
	"slices"
)

// chain puts a handler behind the middleware, the first one outermost.
func chain(middleware ...func(http.Handler) http.Handler) func(http.HandlerFunc) http.Handler {
	return func(fn http.HandlerFunc) http.Handler {
		var h http.Handler = fn
		for _, wrap := range slices.Backward(middleware) {
			h = wrap(h)
		}
		return h
	}
}
