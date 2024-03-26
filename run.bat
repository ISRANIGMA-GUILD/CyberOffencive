@ECHO OFF

REM Run script for Docker container

REM Set the name for the Docker image
SET IMAGE_NAME=servere

REM Set the tag for the Docker image
SET IMAGE_TAG=latest

REM Set the name for the Docker container
SET CONTAINER_NAME=my-python-container

REM Run the Docker container
docker run --rm -it --name %CONTAINER_NAME% %IMAGE_NAME%:%IMAGE_TAG%

REM Clean up or perform any additional tasks if needed

ECHO Run completed.
