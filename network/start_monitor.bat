@echo off
REM Start Network Monitor Container

echo ========================================
echo STARTING NETWORK MONITOR
echo ========================================
echo.

cd /d E:\nos\Network_Security_poc\network

echo Building and starting network-monitor container...
wsl docker-compose up -d --build

echo.
echo Waiting for container to start...
timeout /t 3 /nobreak >nul

wsl docker ps --filter "name=network-monitor" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo.
echo ========================================
echo NETWORK MONITOR STARTED
echo ========================================
echo.
echo Monitor server: http://192.168.6.131:5000
echo HAProxy LB:     http://192.168.6.131:8080
echo HAProxy stats:  http://192.168.6.131:8404
echo.
echo PCAP captures: E:\nos\Network_Security_poc\network\captures\
echo.
echo View logs: docker logs -f network-monitor
echo ========================================
echo.
pause
