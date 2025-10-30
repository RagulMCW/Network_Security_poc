@echo off
REM Stop SSH Brute Force Attacker

echo ========================================
echo Stopping SSH Brute Force Attacker
echo ========================================
echo.

cd /d "%~dp0"

echo Stopping container...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker && docker compose down"

echo.
echo ========================================
echo SSH Attacker Stopped!
echo ========================================
echo.
pause
