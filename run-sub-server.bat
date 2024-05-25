@echo off

start /B cmd /C "dnssec_server.exe"

load_balancer_dnsclient.exe

REM Stop and remove existing containers and networks
docker-compose -f docker-compose.yml down

REM Build and start containers
docker-compose -f docker-compose.yml up
