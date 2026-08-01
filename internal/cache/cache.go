package cache

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("cache: key not found or expired")

// Cache is a TTL-based key-value cache interface.
// Implementations must be safe for concurrent use.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

type entry struct {
	value   []byte
	expires time.Time
}

type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]*entry
}

func NewMemory() *MemoryCache {
	return &MemoryCache{entries: make(map[string]*entry)}
}

func (c *MemoryCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(e.expires) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, ErrNotFound
	}
	// Return a copy so callers can't mutate the cached bytes for all readers.
	return append([]byte(nil), e.value...), nil
}

func (c *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	c.entries[key] = &entry{
		// Store a copy so later mutation of the caller's slice can't corrupt
		// the cached entry through the shared backing array.
		value:   append([]byte(nil), value...),
		expires: time.Now().Add(ttl),
	}
	c.mu.Unlock()
	return nil
}

func (c *MemoryCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return nil
}
