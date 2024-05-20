@echo off

load_balancer_dnsclient.exe

start /B cmd /c "dnssec_server.exe"

REM Stop and remove existing containers and networks
docker-compose -f docker-compose.yml down

REM Build and start containers
docker-compose -f docker-compose.yml up --build
