package cache

import (
	"testing"
	"time"
)

func TestLocal(t *testing.T) {
	c := NewLocal[string](time.Minute)

	if _, ok := c.Get("k"); ok {
		t.Fatal("Get on empty cache = ok, want miss")
	}

	c.Put("k", "v")
	got, ok := c.Get("k")
	if !ok || got != "v" {
		t.Fatalf("Get = (%q, %v), want (v, true)", got, ok)
	}
}

func TestLocalExpiry(t *testing.T) {
	c := NewLocal[string](time.Millisecond)

	c.Put("k", "v")
	time.Sleep(2 * time.Millisecond)

	if _, ok := c.Get("k"); ok {
		t.Fatal("Get after expiry = ok, want miss")
	}
}

func TestLocalOverwrite(t *testing.T) {
	c := NewLocal[string](time.Minute)

	c.Put("k", "v1")
	c.Put("k", "v2")

	got, ok := c.Get("k")
	if !ok || got != "v2" {
		t.Fatalf("Get = (%q, %v), want (v2, true)", got, ok)
	}
}
