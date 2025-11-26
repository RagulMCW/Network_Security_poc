@echo off
REM Rebuild Endpoint Behavior Attacker Container

echo ================================================
echo Rebuilding Endpoint Behavior Attacker
echo ================================================
echo.

cd /d "%~dp0"

echo Stopping existing container...
docker-compose down

echo.
echo Removing old image...
docker rmi endpoint_behavior_attacker_endpoint_behavior_attacker 2>nul

echo.
echo Building new image...
docker-compose build --no-cache

echo.
echo Starting container...
docker-compose up -d

echo.
echo Rebuild complete!
echo View logs with: LOGS.bat
pause
