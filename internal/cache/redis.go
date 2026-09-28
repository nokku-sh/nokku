package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis prefixes keys so the database can be shared with other services.
type Redis struct {
	client *redis.Client
	prefix string
}

func (r *Redis) key(key string) string {
	return r.prefix + key
}

func (r *Redis) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := r.client.Get(ctx, r.key(key)).Bytes()
	if err != nil {
		return nil, mapRedisErr(err)
	}
	return b, nil
}

func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, r.key(key), value, ttl).Err()
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.key(key)).Err()
}

func (r *Redis) GetDel(ctx context.Context, key string) ([]byte, error) {
	b, err := r.client.GetDel(ctx, r.key(key)).Bytes()
	if err != nil {
		return nil, mapRedisErr(err)
	}
	return b, nil
}

func (r *Redis) SetNX(
	ctx context.Context,
	key string,
	value []byte,
	ttl time.Duration,
) (bool, error) {
	return r.client.SetNX(ctx, r.key(key), value, ttl).Result()
}

func mapRedisErr(err error) error {
	if errors.Is(err, redis.Nil) {
		return ErrNotFound
	}
	return err
}
