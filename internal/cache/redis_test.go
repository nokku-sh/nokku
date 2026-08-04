package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisCache(t *testing.T) {
	s := miniredis.RunT(t)
	ctx := context.Background()

	c, err := NewRedis(ctx, s.Addr(), "", 0)
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}

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

func TestRedisCacheExpiry(t *testing.T) {
	s := miniredis.RunT(t)
	ctx := context.Background()

	c, err := NewRedis(ctx, s.Addr(), "", 0)
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}

	key := "exp"
	if err := c.Set(ctx, key, []byte("x"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s.FastForward(time.Minute + time.Second)

	if _, err := c.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after expiry = %v, want ErrNotFound", err)
	}
}

func TestRedisCacheMissing(t *testing.T) {
	s := miniredis.RunT(t)
	ctx := context.Background()

	c, err := NewRedis(ctx, s.Addr(), "", 0)
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}

	if _, err := c.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v, want ErrNotFound", err)
	}
}
