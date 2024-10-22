@echo off

start /B cmd /C "load_balancer_dns.exe"

docker network rm my-network

REM Stop and remove existing containers and networks
docker-compose -f docker-compose-2.yml down 

REM Build and start containers
docker-compose -f docker-compose-2.yml up

docker-compose -f docker-compose-2.yml down

docker network rm my-network