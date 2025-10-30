@echo off
REM Cleanup iptables rules for attacker
REM Run this after stopping/removing the attacker to clear any redirection rules

echo.
echo ========================================
echo Cleaning up iptables rules...
echo ========================================
echo.

wsl bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh

echo.
echo ========================================
echo Done! You can now restart the attacker.
echo ========================================
echo.

pause
