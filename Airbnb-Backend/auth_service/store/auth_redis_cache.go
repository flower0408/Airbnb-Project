package store

import (
	"auth_service/domain"
	"github.com/go-redis/redis"
	"log"
	"time"
)

type AuthRedisCache struct {
	client *redis.Client
}

func NewAuthRedisCache(client *redis.Client) domain.AuthCache {
	return &AuthRedisCache{
		client: client,
	}
}

func (a *AuthRedisCache) PostCacheData(key string, value string) error {
	log.Println("redis post")
	result := a.client.Set(key, value, 10*time.Minute)
	log.Println(result.Err())
	log.Println(result.Result())
	if result.Err() != nil {
		log.Printf("redis set error: %s", result.Err())
		return result.Err()
	}

	return nil
}

func (a *AuthRedisCache) GetCachedValue(key string) (string, error) {
	result := a.client.Get(key)
	token, err := result.Result()
	if err != nil {
		log.Println(err)
		return "", err
	}
	return token, nil
}

func (a *AuthRedisCache) DelCachedValue(key string) error {
	result := a.client.Del(key)
	if result.Err() != nil {
		log.Println(result.Err())
		return result.Err()
	}

	return nil
}
