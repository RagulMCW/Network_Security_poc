@echo off
REM Quick Start - Beelzebub Honeypot
echo ================================================
echo    Beelzebub Honeypot - Quick Start
echo ================================================
echo.

REM Navigate to honey_pot directory
cd /d %~dp0

echo Starting Beelzebub honeypot...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/honey_pot && docker compose -f docker-compose-simple.yml up -d"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to start honeypot!
    pause
    exit /b 1
)

echo.
echo Waiting for services to initialize...
wsl bash -c "sleep 3"

echo.
echo ================================================
echo ✅ Beelzebub Honeypot is Running!
echo ================================================
echo.
echo 🎯 Service Endpoints:
echo   SSH Honeypot:     localhost:2222
echo   HTTP Honeypot:    http://localhost:8080
echo   FTP Honeypot:     localhost:2121
echo   Telnet Honeypot:  localhost:2323
echo   MySQL Honeypot:   localhost:3306
echo   PostgreSQL:       localhost:5432
echo   Log Viewer:       http://localhost:8888/logs
echo.
echo 🧪 Test SSH:
echo   ssh root@localhost -p 2222
echo   Password: root  (or admin, password, 123456)
echo.
echo 🧪 Test HTTP:
echo   http://localhost:8080
echo.
echo 📊 View Dashboard:
echo   http://localhost:5000
echo.
echo 🛑 To stop:
echo   stop_beelzebub_simple.bat
echo.
pause
