@echo off
REM Start Endpoint Behavior Attacker

echo ================================================
echo Starting Endpoint Behavior Attacker
echo Detection Type: Anomaly/Behavior-based (Case 2)
echo ================================================
echo.

cd /d "%~dp0"

echo Building Docker image...
docker-compose build

echo.
echo Starting container...
docker-compose up -d

echo.
echo Container started successfully!
echo.
echo Container Name: endpoint_behavior_attacker
echo IP Address: 192.168.6.201
echo.
echo View logs with: docker logs -f endpoint_behavior_attacker
echo Or use: LOGS.bat
echo.
echo To stop: STOP.bat
pause
