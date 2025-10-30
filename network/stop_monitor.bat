@echo off
REM Stop Network Monitor Container

echo ========================================
echo STOPPING NETWORK MONITOR
echo ========================================
echo.

cd /d E:\nos\Network_Security_poc\network

wsl docker-compose down

echo.
echo Network monitor stopped.
echo.
pause
