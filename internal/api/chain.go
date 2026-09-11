package api

import (
	"net/http"
)

type constructor func(http.Handler) http.Handler

type chain struct {
	constructors []constructor
}

func newChain(constructors ...constructor) chain {
	return chain{append(([]constructor)(nil), constructors...)}
}

func (c chain) Then(h http.Handler) http.Handler {
	if h == nil {
		h = http.DefaultServeMux
	}
	for i := range c.constructors {
		h = c.constructors[len(c.constructors)-1-i](h)
	}
	return h
}

func (c chain) ThenFunc(fn http.HandlerFunc) http.Handler {
	if fn == nil {
		return c.Then(nil)
	}
	return c.Then(fn)
}
