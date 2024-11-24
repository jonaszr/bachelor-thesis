#!/bin/bash

# Remove all containers and volumes produced by docker-compose
docker-compose down -v

# Build and start the services
docker-compose up --build