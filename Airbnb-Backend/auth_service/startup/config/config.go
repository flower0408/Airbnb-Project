package config

import "os"

type Config struct {
	Port          string
	AuthDBHost    string
	AuthDBPort    string
	AuthCacheHost string
	AuthCachePort string
}

func NewConfig() *Config {
	return &Config{
		Port:          os.Getenv("AUTH_SERVICE_PORT"),
		AuthDBHost:    os.Getenv("AUTH_DB_HOST"),
		AuthDBPort:    os.Getenv("AUTH_DB_PORT"),
		AuthCacheHost: os.Getenv("AUTH_CACHE_HOST"),
		AuthCachePort: os.Getenv("AUTH_CACHE_PORT"),
	}
}
