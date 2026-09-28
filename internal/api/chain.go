package api

import (
	"net/http"
	"slices"
)

type constructor func(http.Handler) http.Handler

type chain struct {
	constructors []constructor
}

func newChain(constructors ...constructor) chain {
	return chain{slices.Clone(constructors)}
}

func (c chain) Then(h http.Handler) http.Handler {
	for _, wrap := range slices.Backward(c.constructors) {
		h = wrap(h)
	}
	return h
}

func (c chain) ThenFunc(fn http.HandlerFunc) http.Handler {
	return c.Then(fn)
}
