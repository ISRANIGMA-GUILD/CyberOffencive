@echo off
REM Stop and remove existing containers and networks
docker-compose down

REM Build and start containers
docker-compose up --build
