@echo off

REM create a network

docker network rm my-network

REM Stop and remove existing containers and networks
docker-compose -f docker-compose-2.yml down 

REM Build and start containers
docker-compose -f docker-compose-2.yml up --build
