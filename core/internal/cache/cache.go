// Package cache holds short-lived state, lost on restart and not shared.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// TTL keeps every entry for the same time, so insertion order is expiry order.
// When full it drops the oldest, so a flood never locks out new callers.
type TTL[K comparable, V any] struct {
	mu    sync.Mutex
	ttl   time.Duration
	size  int
	order *list.List // of *entry[K, V], the next to expire first
	items map[K]*list.Element
}

type entry[K comparable, V any] struct {
	key     K
	value   V
	expires time.Time
}

func New[K comparable, V any](size int, ttl time.Duration) *TTL[K, V] {
	return &TTL[K, V]{ttl: ttl, size: max(size, 1), order: list.New(), items: make(map[K]*list.Element)}
}

func (c *TTL[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.liveLocked(key)
}

// Set starts the entry's time over.
func (c *TTL[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value)
}

// SetNX sets key only when it holds nothing live, and reports whether it did.
func (c *TTL[K, V]) SetNX(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.liveLocked(key); ok {
		return false
	}
	c.setLocked(key, value)
	return true
}

// GetDel consumes one-time state, two callers never both get it.
func (c *TTL[K, V]) GetDel(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.liveLocked(key)
	if ok {
		c.removeLocked(key)
	}
	return v, ok
}

func (c *TTL[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

func (c *TTL[K, V]) liveLocked(key K) (V, bool) {
	if el, ok := c.items[key]; ok {
		if e := c.at(el); time.Now().Before(e.expires) {
			return e.value, true
		}
	}
	var zero V
	return zero, false
}

// setLocked evicts from the front: what expired, then the oldest when full.
func (c *TTL[K, V]) setLocked(key K, value V) {
	c.removeLocked(key)
	now := time.Now()
	for el := c.order.Front(); el != nil; el = c.order.Front() {
		e := c.at(el)
		if now.Before(e.expires) && c.order.Len() < c.size {
			break
		}
		c.removeLocked(e.key)
	}
	c.items[key] = c.order.PushBack(&entry[K, V]{key: key, value: value, expires: now.Add(c.ttl)})
}

// at reads an element of order, which only ever holds entries.
func (c *TTL[K, V]) at(el *list.Element) *entry[K, V] {
	e, _ := el.Value.(*entry[K, V])
	return e
}

func (c *TTL[K, V]) removeLocked(key K) {
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}
