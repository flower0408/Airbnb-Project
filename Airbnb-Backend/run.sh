#!/bin/bash

# Run docker inspect to get the IP address of the namenode container
NAMENODE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' namenode)

# Set the obtained IP address in an environment variable
export NAMENODE_IP

# Run docker-compose
docker-compose up

