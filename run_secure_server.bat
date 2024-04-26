@ECHO OFF

REM Run script for Docker container

REM Set the name for the Docker image
SET IMAGE_NAME=secure_server

REM Set the tag for the Docker image
SET IMAGE_TAG=latest

REM Set the name for the Docker container
SET CONTAINER_NAME=secure-server-container

REM Generate a random port between 443 and 500
SET /A RANDOM_PORT=(443 + %RANDOM% %% (500 - 443 + 1))

REM Check if the network exists
docker network inspect my_network > nul 2>&1
IF ERRORLEVEL 1 (
    REM Create the Docker network if it doesn't exist
    docker network create my_network
)

REM Run the Docker container with dynamic port allocation and port mapping
docker run --rm -t -p %RANDOM_PORT%:443 -p 53:53 --name %CONTAINER_NAME% --network my_network %IMAGE_NAME%:%IMAGE_TAG%

REM Clean up or perform any additional tasks if needed

ECHO Run completed.
