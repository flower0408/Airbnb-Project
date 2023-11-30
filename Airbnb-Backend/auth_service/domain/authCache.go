package domain

type AuthCache interface {
	PostCacheData(key string, value string) error
	GetCachedValue(key string) (string, error)
	DelCachedValue(key string) error
}
