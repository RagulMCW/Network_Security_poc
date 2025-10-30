@echo off
REM Fix Dashboard Port Conflict
REM The network-monitor uses port 5000, so dashboard now uses 5100

echo ========================================
echo Dashboard Port Fix
echo ========================================
echo.
echo Issue: Port 5000 was being used by BOTH:
echo   1. Network Monitor (Docker container)
echo   2. Dashboard (Flask app)
echo.
echo Solution: Dashboard moved to port 5100
echo.
echo ========================================
echo.

REM Stop any running dashboard on old port
echo Checking for processes on port 5000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    echo Found process: %%a
    tasklist /FI "PID eq %%a" | findstr python >nul
    if not errorlevel 1 (
        echo Stopping Python dashboard on port 5000 (PID: %%a)
        taskkill /F /PID %%a >nul 2>&1
    )
)

echo.
echo ========================================
echo Starting Dashboard on Port 5100
echo ========================================
echo.

cd /d "%~dp0"
start_dashboard.bat
