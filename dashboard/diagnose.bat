@echo off
echo ========================================
echo Device Connection Diagnostics
echo ========================================
echo.

echo [1/6] Checking if dashboard is running...
curl -s http://localhost:5000/api/status >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Dashboard is running on localhost:5000
) else (
    echo [FAIL] Dashboard is NOT running on localhost:5000
    echo        Please start the dashboard first!
    echo        Run: restart_dashboard.bat
    goto :end
)

echo.
echo [2/6] Checking Docker network...
wsl docker network inspect custom_net >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Docker network 'custom_net' exists
) else (
    echo [FAIL] Docker network 'custom_net' does NOT exist
    echo        Create it from the dashboard Overview page
    goto :end
)

echo.
echo [3/6] Testing dashboard from Docker network...
wsl docker run --rm --network custom_net alpine wget -qO- http://192.168.6.1:5000/api/status >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Dashboard is accessible from Docker network at 192.168.6.1:5000
) else (
    echo [FAIL] Dashboard is NOT accessible from Docker network
    echo        Possible causes:
    echo        - Windows Firewall blocking port 5000
    echo        - Dashboard not listening on 0.0.0.0
    echo        - Network configuration issue
    goto :end
)

echo.
echo [4/6] Checking for running devices...
for /f %%i in ('wsl docker ps --filter name^=device_ --format "{{.Names}}" ^| wc -l') do set DEVICE_COUNT=%%i
echo Found %DEVICE_COUNT% running device containers

echo.
echo [5/6] Checking device logs for errors...
wsl docker ps --filter name=device_ --format "{{.Names}}" > temp_devices.txt
for /f %%d in (temp_devices.txt) do (
    echo.
    echo Checking %%d...
    wsl docker logs --tail 5 %%d 2>&1 | findstr /C:"Connection refused" >nul
    if %errorlevel% equ 0 (
        echo [FAIL] %%d has connection errors
    ) else (
        echo [OK] %%d appears to be working
    )
)
del temp_devices.txt >nul 2>&1

echo.
echo [6/6] Firewall check...
netstat -ano | findstr :5000 >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Port 5000 is listening
    netstat -ano | findstr :5000 | findstr LISTENING
) else (
    echo [FAIL] Port 5000 is not listening
)

echo.
echo ========================================
echo Diagnostic Summary
echo ========================================
echo.
echo If all checks passed:
echo   - Your setup is working correctly!
echo.
echo If any checks failed:
echo   1. Read the error messages above
echo   2. Check TROUBLESHOOTING.md for solutions
echo   3. Restart dashboard: restart_dashboard.bat
echo   4. Recreate devices from the UI
echo.

:end
pause
