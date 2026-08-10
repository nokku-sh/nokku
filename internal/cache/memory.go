package cache

import (
	"context"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// maxMemoryEntries caps the number of entries the memory cache holds to
// prevent unbounded growth. When full, the least-recently-used entry is
// evicted.
const maxMemoryEntries = 10_000

// memorySweepTTL bounds how long an entry may sit in the memory cache before
// the library's janitor reclaims it. Per-key TTLs are enforced separately, so
// this only needs to exceed the longest per-key TTL the cache is asked to
// hold. Refresh-token reuse state lives for the 7-day refresh lifetime, hence
// 8 days.
const memorySweepTTL = 8 * 24 * time.Hour

type entry struct {
	value   []byte
	expires time.Time
}

// MemoryCache is an in-memory, size-bounded Cache. It is safe for concurrent
// use. Entries expire on a per-key TTL and the least-recently-used entry is
// evicted when the cache reaches maxMemoryEntries.
type MemoryCache struct {
	lru *expirable.LRU[string, *entry]
}

func NewMemory() *MemoryCache {
	return newMemory(maxMemoryEntries, memorySweepTTL)
}

func newMemory(size int, ttl time.Duration) *MemoryCache {
	return &MemoryCache{
		lru: expirable.NewLRU[string, *entry](size, nil, ttl),
	}
}

func (c *MemoryCache) Get(_ context.Context, key string) ([]byte, error) {
	e, ok := c.lru.Get(key)
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(e.expires) {
		c.lru.Remove(key)
		return nil, ErrNotFound
	}
	// Return a copy so callers can't mutate the cached bytes for all readers.
	return append([]byte(nil), e.value...), nil
}

func (c *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.lru.Add(key, &entry{
		// Store a copy so later mutation of the caller's slice can't corrupt
		// the cached entry through the shared backing array.
		value:   append([]byte(nil), value...),
		expires: time.Now().Add(ttl),
	})
	return nil
}

func (c *MemoryCache) Delete(_ context.Context, key string) error {
	c.lru.Remove(key)
	return nil
}
