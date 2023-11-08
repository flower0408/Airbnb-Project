package main

import (
	"user_service/startup"
	"user_service/startup/config"
)

func main() {
	cfg := config.NewConfig()
	server := startup.NewServer(cfg)
	server.Start()

}
