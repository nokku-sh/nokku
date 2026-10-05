package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemory(t *testing.T) {
	c := NewMemory(10)
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

	if _, err := c.Get(ctx, key); !errors.Is(err, errNotFound) {
		t.Fatalf("Get after Delete = %v, want errNotFound", err)
	}
}

func TestMemoryExpiry(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	if err := c.Set(ctx, "k", []byte("v"), time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	if _, err := c.Get(ctx, "k"); !errors.Is(err, errNotFound) {
		t.Fatalf("Get after expiry = %v, want errNotFound", err)
	}
}

// Set stores a copy of the value: later mutation of the caller's slice must
// not corrupt the cached entry.
func TestMemorySetCopies(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	value := []byte("hello")
	if err := c.Set(ctx, "k", value, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	value[0] = 'X'

	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Get = %q, want the original value", got)
	}
}

func TestMemoryGetDel(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	if err := c.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := c.GetDel(ctx, "k")
	if err != nil {
		t.Fatalf("GetDel: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("GetDel = %q, want %q", got, "v")
	}
	// Second consumer finds nothing: single-use state.
	if _, err := c.GetDel(ctx, "k"); !errors.Is(err, errNotFound) {
		t.Fatalf("second GetDel = %v, want errNotFound", err)
	}
}

func TestMemorySetNX(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	first, err := c.SetNX(ctx, "k", []byte("v1"), time.Minute)
	if err != nil {
		t.Fatalf("SetNX: %v", err)
	}
	if !first {
		t.Fatal("first SetNX = false, want true")
	}

	second, err := c.SetNX(ctx, "k", []byte("v2"), time.Minute)
	if err != nil {
		t.Fatalf("second SetNX: %v", err)
	}
	if second {
		t.Fatal("second SetNX = true, want false")
	}

	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v1" {
		t.Fatalf("Get = %q, want the first value", got)
	}
}

// A consumed key frees its slot: SetNX after expiry must win again.
func TestMemorySetNXAfterExpiry(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	if _, err := c.SetNX(ctx, "k", []byte("v"), time.Millisecond); err != nil {
		t.Fatalf("SetNX: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	got, err := c.SetNX(ctx, "k", []byte("v2"), time.Minute)
	if err != nil {
		t.Fatalf("SetNX after expiry: %v", err)
	}
	if !got {
		t.Fatal("SetNX after expiry = false, want true")
	}
}

// A cache full of live entries refuses new keys instead of evicting, so no
// caller can push out someone else's state.
func TestMemoryFullRefusesNewKeys(t *testing.T) {
	c := NewMemory(2)
	ctx := t.Context()

	for _, k := range []string{"a", "b"} {
		if err := c.Set(ctx, k, []byte(k), time.Minute); err != nil {
			t.Fatalf("Set %q: %v", k, err)
		}
	}
	if err := c.Set(ctx, "c", nil, time.Minute); !errors.Is(err, errFull) {
		t.Fatalf("Set on a full cache: err = %v, want errFull", err)
	}
	if added, err := c.SetNX(ctx, "c", nil, time.Minute); added || !errors.Is(err, errFull) {
		t.Fatalf("SetNX on a full cache = %v, %v, want false, errFull", added, err)
	}
	for _, k := range []string{"a", "b"} {
		if _, err := c.Get(ctx, k); err != nil {
			t.Errorf("live entry %q gone: %v", k, err)
		}
	}
	// An existing key needs no room.
	if err := c.Set(ctx, "a", []byte("new"), time.Minute); err != nil {
		t.Fatalf("overwrite on a full cache: %v", err)
	}
	if err := c.Delete(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "c", nil, time.Minute); err != nil {
		t.Fatalf("Set after a delete made room: %v", err)
	}
}

// A zero or negative TTL means no expiry: the entry stays until deleted.
func TestMemoryNoTTL(t *testing.T) {
	c := NewMemory(10)
	ctx := context.Background()

	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := c.Get(ctx, "k"); err != nil {
		t.Fatalf("Get without TTL: %v", err)
	}
}

// A full cache makes room from expired entries, and SetNX is bounded too, so
// replay markers cannot grow the cache forever.
func TestMemoryEvictsExpiredFirst(t *testing.T) {
	c := NewMemory(2)
	ctx := t.Context()
	if _, err := c.SetNX(ctx, "old", nil, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetNX(ctx, "live", nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := c.SetNX(ctx, "new", nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, "live"); err != nil {
		t.Errorf("live entry evicted while an expired one was available: %v", err)
	}
	if n := len(c.entries); n > 2 {
		t.Errorf("cache holds %d entries, want at most 2", n)
	}
}
