@echo off
REM ============================================
REM Stop Honeypot Services
REM ============================================

cd /d "%~dp0"

echo.
echo ========================================
echo   STOPPING HONEYPOT
echo ========================================
echo.

docker-compose -f docker-compose-simple.yml down

echo.
echo [SUCCESS] Honeypot stopped
echo.
