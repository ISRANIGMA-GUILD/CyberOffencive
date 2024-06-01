@echo off

start /B cmd /C "dnssec_server.exe"

load_balancer_dnsclient.exe

docker network create --driver bridge my-network

REM Stop and remove existing containers and networks
docker-compose -f docker-compose.yml down

REM Build and start containers
<<<<<<< HEAD
docker-compose -f docker-compose.yml up
=======
docker-compose -f docker-compose.yml up

docker-compose -f docker-compose.yml down

docker network rm my-network
>>>>>>> f7060b43e8b54043aa7e2bd6754d2182fe4b0502
