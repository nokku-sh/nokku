// Package cache holds short-lived state in the process: login flow state,
// DPoP replay markers, mail cooldowns, and terminal tickets. It is lost on a
// restart and not shared, the server runs as one instance.
package cache

import "errors"

var errNotFound = errors.New("cache: not found")
