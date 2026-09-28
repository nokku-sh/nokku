// Package cache holds cross-request state. Run more than one instance only
// with Redis, or single-use state is not shared.
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache one-time state must be consumed through GetDel, so concurrent
// consumers can never both succeed.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	GetDel(ctx context.Context, key string) ([]byte, error)
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

var ErrNotFound = errors.New("cache: not found")

// New uses Redis when NOKKU_REDIS_URL is set, memory otherwise.
func New(ctx context.Context) (Cache, error) {
	url := os.Getenv("NOKKU_REDIS_URL")
	if url == "" {
		return NewMemory(10_000), nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("cache: invalid NOKKU_REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("cache: ping redis: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = client.Close()
	}()
	return &Redis{client: client, prefix: "nokku:"}, nil
}
