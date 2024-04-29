# Dockerfile
FROM python:3.11-slim-bullseye

# Expose the required ports
EXPOSE 8820/tcp
EXPOSE 6921/tcp
EXPOSE 8843/tcp
EXPOSE 443/tcp
EXPOSE 1800/tcp

# update reposatories
RUN apt update -y && apt upgrade -y
RUN apt install -y gcc python3-dev libpcap-dev

# Set the working directory
WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install -r /app/requirements.txt
RUN pip install https://github.com/secdev/scapy/archive/refs/heads/master.zip

# Copy the game script
COPY . .

# Set any environment variables if needed

# Run the game script
CMD ["python", "Game/src/code/the_server.py"]