package domain

import "context"

type AuthCache interface {
	PostCacheData(ctx context.Context, key string, value string) error
	GetCachedValue(ctx context.Context, key string) (string, error)
	DelCachedValue(ctx context.Context, key string) error
}
