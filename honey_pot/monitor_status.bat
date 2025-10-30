@echo off
REM Windows wrapper to check honeypot monitoring status

echo Running honeypot monitoring check in WSL...
echo.

wsl bash /mnt/e/nos/Network_Security_poc/honey_pot/monitor_status.sh

echo.
pause
