@echo off
REM Start Network Monitor Container

title Start Network Monitor

echo.
echo ================================================================
echo    STARTING NETWORK MONITOR
echo ================================================================
echo.

cd /d %~dp0

echo Checking if custom_net network exists...
wsl bash -c "docker network inspect custom_net >/dev/null 2>&1 || docker network create --driver bridge --subnet 192.168.6.0/24 custom_net"
echo.

echo Building and starting network-monitor container...
wsl bash -c "cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/network && docker-compose up -d --build"

if %errorlevel% neq 0 (
    echo ✗ Failed to start network monitor
    pause
    exit /b 1
)

echo.
echo Ensuring Docker inter-container communication rules...
call "%~dp0..\scripts\ensure_docker_icc.bat"

echo.
echo ================================================================
echo ✓ NETWORK MONITOR STARTED
echo ================================================================
echo.
echo Container: network-monitor
echo IP: 192.168.6.131
echo Port: 5000 (Flask API)
echo.
echo Dashboard should now connect successfully!
echo ================================================================
echo.
pause
