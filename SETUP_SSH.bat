@echo off
REM Setup SSH Server and Attacker
REM This script will rebuild the network monitor with SSH and start the SSH attacker

echo ========================================
echo SSH Server and Attacker Setup
echo ========================================
echo.
echo This will:
echo   1. Rebuild network monitor with SSH server (192.168.6.131:22)
echo   2. Build SSH brute force attacker (192.168.6.133)
echo   3. Start both containers
echo.
pause

echo.
echo [1/3] Stopping existing containers...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/network && docker-compose down"
echo.

echo [2/3] Rebuilding network monitor with SSH server...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/network && docker compose up -d --build"
echo.

echo Waiting for network monitor to start...
timeout /t 10 /nobreak >nul

echo.
echo [3/3] Building SSH attacker...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker && docker compose build"
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo SSH Server is now running on:
echo   Internal: 192.168.6.131:22
echo   External: localhost:2222
echo.
echo Test SSH accounts:
echo   root:rootpassword
echo   admin:admin123
echo   test:test123
echo   user:password
echo.
echo Test SSH connection:
echo   wsl ssh -p 2222 admin@localhost
echo.
echo Start SSH attacker from dashboard or run:
echo   E:\nos\Network_Security_poc\attackers\ssh_attacker\START_SSH_ATTACKER.bat
echo.
pause
