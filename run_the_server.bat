@ECHO OFF

REM Run script for Docker container

REM Set the name for the Docker image
SET IMAGE_NAME=the_server

REM Set the tag for the Docker image
SET IMAGE_TAG=latest

REM Set the name for the Docker container
SET CONTAINER_NAME=the-server-container

REM Check if the network exists
docker network inspect my_network > nul 2>&1
IF ERRORLEVEL 1 (
    REM Create the Docker network if it doesn't exist
    docker network create my_network
)

REM Run the Docker container with dynamic port allocation
docker run --rm -t -p 1024-1100:1024-1100 --name %CONTAINER_NAME% --network my_network %IMAGE_NAME%:%IMAGE_TAG%

REM Clean up or perform any additional tasks if needed

ECHO Run completed.
