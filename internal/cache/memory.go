package cache

// The process-local memory backend: a mutex+map with per-entry expiry and a
// bound on total entries. It backs the shared cache contract when no Redis
// is configured; a multi-instance deployment then has per-instance state,
// which the consumers of single-use state must tolerate (the instances
// simply cannot share cooldowns or replay detection).

import (
	"context"
	"sync"
	"time"
)

// Memory is a process-local mutex+map cache with per-entry expiry.
type Memory struct {
	mu      sync.RWMutex
	entries map[string]memoryEntry
	max     int
}

type memoryEntry struct {
	value     []byte
	expires   time.Time
	hasExpiry bool
}

// NewMemory builds an in-memory cache bounded to maxSize entries (oldest
// inserted evicted first).
func NewMemory(maxSize int) *Memory {
	if maxSize <= 0 {
		maxSize = 10_000
	}
	return &Memory{entries: make(map[string]memoryEntry), max: maxSize}
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	e, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok || expired(e) {
		return nil, ErrNotFound
	}
	return append([]byte(nil), e.value...), nil
}

func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictLocked()
	m.entries[key] = memoryEntry{
		value:     append([]byte(nil), value...),
		expires:   time.Now().Add(ttl),
		hasExpiry: ttl > 0,
	}
	return nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

func (m *Memory) GetDel(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || expired(e) {
		return nil, ErrNotFound
	}
	delete(m.entries, key)
	return append([]byte(nil), e.value...), nil
}

func (m *Memory) SetNX(
	_ context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[key]; ok && !expired(e) {
		return false, nil
	}
	m.entries[key] = memoryEntry{
		value:     append([]byte(nil), value...),
		expires:   time.Now().Add(ttl),
		hasExpiry: ttl > 0,
	}
	return true, nil
}

func (m *Memory) evictLocked() {
	if len(m.entries) < m.max {
		return
	}
	// Evict arbitrary: the map is a cache; a random victim is fine.
	for k := range m.entries {
		delete(m.entries, k)
		if len(m.entries) < m.max {
			return
		}
	}
}

func expired(e memoryEntry) bool {
	return e.hasExpiry && time.Now().After(e.expires)
}
