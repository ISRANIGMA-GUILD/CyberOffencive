@ECHO OFF

REM Build script for Docker container

REM Set the path to the Dockerfile
SET DOCKERFILE=Dockerfile_secure_server

REM Set the name for the Docker image
SET IMAGE_NAME=servere

REM Set the tag for the Docker image
SET IMAGE_TAG=latest

REM Build the Docker image
docker build -t %IMAGE_NAME%:%IMAGE_TAG% -f %DOCKERFILE% .

REM Clean up temporary files or any other cleanup steps if needed

ECHO Faild succsesfully
