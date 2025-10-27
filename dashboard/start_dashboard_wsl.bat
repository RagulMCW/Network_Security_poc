@echo off
REM Start Flask dashboard in WSL so Docker devices can reach it

echo.
echo ========================================
echo  Starting Dashboard in WSL
echo ========================================
echo.
echo This will make the dashboard accessible to:
echo   - Docker devices at http://192.168.6.1:5000
echo   - Your browser at http://localhost:5000
echo.
echo Press Ctrl+C to stop the dashboard
echo.

wsl bash /mnt/e/nos/Network_Security_poc/dashboard/start_dashboard_wsl.sh
