@echo off
REM Start All Network Security POC Services

echo ========================================
echo STARTING ALL SERVICES
echo ========================================
echo.

wsl bash /mnt/e/nos/Network_Security_poc/start_all.sh

echo.
echo Press any key to continue...
pause >nul
