@echo off

rem Get the IP address of the default network interface
for /f "tokens=2 delims=: " %%i in ('powershell Get-NetIPAddress -PrefixOrigin Dhcp ^| findstr /C:"IPAddress"') do (
    echo Found IP Address: %%i
    set "IPAddress=%%i"
)

echo "IP Address: %IPAddress%"

rem Get the default gateway
for /f "tokens=3" %%i in ('route print ^| findstr /C:"0.0.0.0"') do (
    echo Found Default Gateway: %%i
    set "DefaultGateway=%%i"
)

rem Update Docker daemon configuration
(
  echo {
  echo   "bip": "%IPAddress:/16%/24",
  echo   "default-gateway": "%DefaultGateway%"
  echo }
) > "C:\ProgramData\Docker\config\daemon.json"

rem Restart Docker service
echo Restarting Docker service...
net stop docker
net start docker
echo Docker service restarted.


REM Stop and remove existing containers and networks
docker-compose down

REM Build and start containers
docker-compose up --build
