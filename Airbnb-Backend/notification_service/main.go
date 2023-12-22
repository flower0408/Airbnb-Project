package main

import (
	"notification_service/startup"
	"notification_service/startup/config"
)

func main() {
	cfg := config.NewConfig()
	server := startup.NewServer(cfg)
	server.Start()

}
