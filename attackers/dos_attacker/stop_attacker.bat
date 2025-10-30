@echo off
REM Stop attacker and cleanup iptables rules

echo ========================================
echo Stopping DoS Attacker
echo ========================================
echo.

echo [1/2] Cleaning up iptables rules...
wsl bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.132

echo.
echo [2/2] Stopping Docker container...
docker-compose down

echo.
echo ========================================
echo Attacker stopped and cleaned up!
echo ========================================
pause
