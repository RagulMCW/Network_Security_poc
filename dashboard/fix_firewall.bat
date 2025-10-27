@echo off
echo ========================================
echo Adding Windows Firewall Rule
echo ========================================
echo.
echo This will allow Docker containers to reach the dashboard on port 5000
echo.

netsh advfirewall firewall delete rule name="Flask Dashboard - Docker Network" >nul 2>&1
netsh advfirewall firewall add rule name="Flask Dashboard - Docker Network" dir=in action=allow protocol=TCP localport=5000

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Firewall rule added successfully!
    echo.
    echo Docker containers can now communicate with dashboard at 192.168.6.1:5000
    echo.
) else (
    echo.
    echo [FAILED] Could not add firewall rule
    echo Please run this script as Administrator
    echo.
)

pause
