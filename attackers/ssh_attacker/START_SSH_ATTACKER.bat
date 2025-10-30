@echo off
REM Start SSH Brute Force Attacker
REM This will launch the SSH attacker container

echo ========================================
echo Starting SSH Brute Force Attacker
echo ========================================
echo.
echo Target: 192.168.6.131:22
echo Attacker IP: 192.168.6.133
echo Attack Interval: 5 seconds
echo Log Dump Interval: 5 seconds
echo.

cd /d "%~dp0"

echo Starting container...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker && docker compose up -d"

echo.
echo ========================================
echo SSH Attacker Started!
echo ========================================
echo.
echo View logs with:
echo   docker logs -f ssh-attacker
echo.
echo Or in WSL:
echo   wsl docker logs -f ssh-attacker
echo.
echo Stop with:
echo   STOP_SSH_ATTACKER.bat
echo.
pause
