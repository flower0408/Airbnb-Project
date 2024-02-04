package store

import (
	"auth_service/domain"
	"context"
	"github.com/go-redis/redis"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"log"
	"time"
)

type AuthRedisCache struct {
	client *redis.Client
	tracer trace.Tracer
}

func NewAuthRedisCache(client *redis.Client, tracer trace.Tracer) domain.AuthCache {
	return &AuthRedisCache{
		client: client,
		tracer: tracer,
	}
}

func (a *AuthRedisCache) PostCacheData(ctx context.Context, key string, value string) error {
	ctx, span := a.tracer.Start(ctx, "AuthRedisCache.PostCacheData")
	defer span.End()

	result := a.client.Set(key, value, 10*time.Minute)
	if result.Err() != nil {
		span.SetStatus(codes.Error, "Error posting cached value")
		log.Printf("redis set error: %s", result.Err())
		return result.Err()
	}

	return nil
}

func (a *AuthRedisCache) GetCachedValue(ctx context.Context, key string) (string, error) {
	ctx, span := a.tracer.Start(ctx, "AuthRedisCache.GetCachedValue")
	defer span.End()

	result := a.client.Get(key)
	token, err := result.Result()
	if err != nil {
		span.SetStatus(codes.Error, "Error getting cached value")
		log.Println(err)
		return "", err
	}
	return token, nil
}

func (a *AuthRedisCache) DelCachedValue(ctx context.Context, key string) error {
	ctx, span := a.tracer.Start(ctx, "AuthRedisCache.DelCachedValue")
	defer span.End()

	result := a.client.Del(key)
	if result.Err() != nil {
		span.SetStatus(codes.Error, "Error deleting cached value")
		log.Println(result.Err())
		return result.Err()
	}

	return nil
}
