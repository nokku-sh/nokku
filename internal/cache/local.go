package cache

// Local is the second cache flavor: typed, process-local, and reconstructible.
// It memoizes expensive parsed objects — discovered OIDC provider endpoints,
// parsed SAML IdP metadata — that are public data: a losing instance just
// re-fetches, so there is nothing to share and no atomicity to preserve.
// That is why it is not a Cache implementation: the values are not bytes,
// and GetDel/SetNX semantics would be meaningless for it.

import (
	"sync"
	"time"
)

// Local is a process-local typed cache with per-entry expiry. Safe for
// concurrent use.
type Local[T any] struct {
	mu      sync.Mutex
	entries map[string]localEntry[T]
	ttl     time.Duration
}

type localEntry[T any] struct {
	value     T
	expiresAt time.Time
}

// NewLocal builds a process-local cache whose entries expire after ttl.
func NewLocal[T any](ttl time.Duration) *Local[T] {
	return &Local[T]{entries: make(map[string]localEntry[T]), ttl: ttl}
}

// Get returns the cached value for key and whether it is present and fresh.
func (c *Local[T]) Get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		var zero T
		return zero, false
	}
	return e.value, true
}

// Put stores value under key until the cache TTL elapses.
func (c *Local[T]) Put(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = localEntry[T]{value: v, expiresAt: time.Now().Add(c.ttl)}
}
