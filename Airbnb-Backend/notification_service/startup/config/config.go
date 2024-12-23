package config

import "os"

type Config struct {
	Port               string
	NotificationDBHost string
	NotificationDBPort string
	JaegerAddress      string
}

func NewConfig() *Config {
	return &Config{
		Port:               os.Getenv("NOTIFICATION_SERVICE_PORT"),
		NotificationDBHost: os.Getenv("NOTIFICATION_DB_HOST"),
		NotificationDBPort: os.Getenv("NOTIFICATION_DB_PORT"),
		JaegerAddress:      os.Getenv("JAEGER_ADDRESS"),
	}
}
