package cache

import (
	"context"
	"errors"
	"time"

	"github.com/caarlos0/env/v11"
)

var ErrNotFound = errors.New("cache: key not found or expired")

// Cache is a TTL-based key-value cache interface.
// Implementations must be safe for concurrent use.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// Config configures the cache backend from environment variables.
type Config struct {
	Backend       string `env:"NOKKU_CACHE"          envDefault:"memory"`
	RedisAddr     string `env:"NOKKU_REDIS_ADDR"     envDefault:"localhost:6379"`
	RedisPassword string `env:"NOKKU_REDIS_PASSWORD"`
	RedisDB       int    `env:"NOKKU_REDIS_DB"       envDefault:"0"`
}

// New parses the cache environment configuration and returns the selected
// backend. Unknown or empty backends fall back to the in-memory cache.
func New(ctx context.Context) (Cache, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, err
	}

	switch cfg.Backend {
	case "redis":
		return NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	default:
		return NewMemory(), nil
	}
}
