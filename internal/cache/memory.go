package cache

import (
	"context"
	"maps"
	"sync"
	"time"
)

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
		return nil, errNotFound
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

// GetDel is how one-time state is consumed, so two concurrent consumers can
// never both succeed.
func (m *Memory) GetDel(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || expired(e) {
		return nil, errNotFound
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
	m.evictLocked()
	m.entries[key] = memoryEntry{
		value:     append([]byte(nil), value...),
		expires:   time.Now().Add(ttl),
		hasExpiry: ttl > 0,
	}
	return true, nil
}

// evictLocked drops expired entries before live ones.
func (m *Memory) evictLocked() {
	if len(m.entries) < m.max {
		return
	}
	maps.DeleteFunc(m.entries, func(_ string, e memoryEntry) bool { return expired(e) })
	for k := range m.entries {
		if len(m.entries) < m.max {
			return
		}
		delete(m.entries, k)
	}
}

func expired(e memoryEntry) bool {
	return e.hasExpiry && time.Now().After(e.expires)
}
