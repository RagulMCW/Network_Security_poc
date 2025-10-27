@echo off
REM Stop Beelzebub Honeypot
echo ================================================
echo   Stopping Beelzebub Honeypot
echo ================================================
echo.

cd /d %~dp0

wsl bash -c "cd /mnt/e/nos/Network_Security_poc/honey_pot && docker compose -f docker-compose-simple.yml down"

echo.
echo ✅ Honeypot stopped.
echo.
pause
