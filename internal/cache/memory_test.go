package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	c := NewMemory()
	ctx := context.Background()

	key := "k"
	value := []byte("hello")

	if err := c.Set(ctx, key, value, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(value) {
		t.Fatalf("Get = %q, want %q", got, value)
	}

	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestMemoryCacheExpiry(t *testing.T) {
	c := newMemory(10, time.Hour)
	ctx := context.Background()

	key := "exp"
	if err := c.Set(ctx, key, []byte("x"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := c.Get(ctx, key); err != nil {
		t.Fatalf("Get before expiry: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after expiry = %v, want ErrNotFound", err)
	}
}

func TestMemoryCacheEvictsOldest(t *testing.T) {
	c := newMemory(2, time.Hour)
	ctx := context.Background()

	if err := c.Set(ctx, "a", []byte("1"), time.Minute); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := c.Set(ctx, "b", []byte("2"), time.Minute); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	// Touching "a" makes "b" the least-recently-used entry.
	if _, err := c.Get(ctx, "a"); err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if err := c.Set(ctx, "c", []byte("3"), time.Minute); err != nil {
		t.Fatalf("Set c: %v", err)
	}

	if _, err := c.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get evicted b = %v, want ErrNotFound", err)
	}
	if _, err := c.Get(ctx, "a"); err != nil {
		t.Fatalf("Get a after eviction: %v", err)
	}
}
