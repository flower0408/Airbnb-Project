package config

import "os"

type Config struct {
	Port                 string
	RecommendationDBHost string
	RecommendationDBPort string
	RecommendationDBUser string
	RecommendationDBPass string
	JaegerAddress        string
}

func NewConfig() *Config {
	return &Config{
		Port:                 os.Getenv("RECOMMENDATION_SERVICE_PORT"),
		RecommendationDBHost: os.Getenv("RECOMMENDATION_DB_HOST"),
		RecommendationDBPort: os.Getenv("RECOMMENDATION_DB_PORT"),
		RecommendationDBUser: os.Getenv("RECOMMENDATION_DB_USER"),
		RecommendationDBPass: os.Getenv("RECOMMENDATION_DB_PASS"),
		JaegerAddress:        os.Getenv("JAEGER_ADDRESS"),
	}
}
