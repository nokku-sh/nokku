// Package cache is nokku's shared cache: email cooldowns, DPoP replay
// detection, SSO flow state, and future cross-request state. Redis when
// REDIS_ADDR is set, process-local memory otherwise.
//
// Two flavors live here:
//   - Cache implementations (Memory, Redis) are shared, byte-oriented, and
//     provide the atomic operations single-use state needs (GetDel, SetNX).
//   - Local[T] is a typed, process-local memoization cache for
//     reconstructible public data, where sharing across instances would buy
//     nothing and atomicity does not matter.
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache is the shared cache contract. One-time state must be consumed
// through GetDel, so concurrent consumers can never both succeed.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	GetDel(ctx context.Context, key string) ([]byte, error)
	// SetNX stores value only when key is absent and reports whether it did.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

// ErrNotFound is the sentinel for missing keys; callers match with [errors.Is].
var ErrNotFound = errors.New("cache: not found")

// New builds the shared cache from the environment: Redis when REDIS_ADDR is
// set, memory otherwise.
func New(ctx context.Context) (Cache, error) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		return NewMemory(10_000), nil
	}

	db, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, fmt.Errorf("cache: invalid REDIS_DB: %w", err)
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       db,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("cache: ping redis: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = client.Close()
	}()
	return NewRedis(client, "nokku:"), nil
}
