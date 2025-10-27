@echo off
echo ========================================
echo Restarting Network Security Dashboard
echo ========================================
echo.

taskkill /F /IM python.exe /FI "WINDOWTITLE eq *app.py*" 2>nul
timeout /t 2 /nobreak >nul

cd /d "%~dp0"
start "Network Security Dashboard" python app.py

echo.
echo Dashboard restarted!
echo Open: http://localhost:5000
echo.
pause
