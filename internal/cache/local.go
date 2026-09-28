package cache

import (
	"sync"
	"time"
)

// Local memoizes reconstructible public data, so it needs no sharing or
// atomicity.
type Local[T any] struct {
	mu      sync.Mutex
	entries map[string]localEntry[T]
	ttl     time.Duration
}

type localEntry[T any] struct {
	value     T
	expiresAt time.Time
}

func NewLocal[T any](ttl time.Duration) *Local[T] {
	return &Local[T]{entries: make(map[string]localEntry[T]), ttl: ttl}
}

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

func (c *Local[T]) Put(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = localEntry[T]{value: v, expiresAt: time.Now().Add(c.ttl)}
}
