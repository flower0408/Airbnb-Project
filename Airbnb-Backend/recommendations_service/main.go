package main

import (
	"recommendations_service/startup"
	"recommendations_service/startup/config"
)

func main() {
	cfg := config.NewConfig()
	server := startup.NewServer(cfg)
	server.Start()

}
