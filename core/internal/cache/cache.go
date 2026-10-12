// Package cache holds short-lived state in the process. It is lost on a restart and not shared.
package cache

import "errors"

var (
	errNotFound = errors.New("cache: not found")
	errFull     = errors.New("cache: full")
)
