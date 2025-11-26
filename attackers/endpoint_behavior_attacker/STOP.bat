@echo off
REM Stop Endpoint Behavior Attacker

echo ================================================
echo Stopping Endpoint Behavior Attacker
echo ================================================
echo.

cd /d "%~dp0"

docker-compose down

echo.
echo Container stopped successfully!
pause
