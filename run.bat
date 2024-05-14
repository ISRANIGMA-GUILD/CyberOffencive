@echo off

python Game\src\code\load_balancer_dnsclient.py

REM Stop and remove existing containers and networks
docker-compose -f docker-compose.yml down

REM Build and start containers
docker-compose -f docker-compose.yml up --build
