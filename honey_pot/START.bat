@echo off
REM ============================================
REM Automated Honeypot Startup Script
REM Starts Beelzebub with Gemini AI + PCAP
REM ============================================

cd /d "%~dp0"

echo.
echo ========================================
echo   HONEYPOT AUTOMATED STARTUP
echo ========================================
echo.

REM Check if already running
docker ps --filter "name=beelzebub-honeypot" --format "{{.Names}}" | findstr /i "beelzebub-honeypot" >nul
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Honeypot is already running
    echo.
    docker ps --filter "name=beelzebub" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo.
    goto :EOF
)

REM Create directories
if not exist "logs" mkdir logs
if not exist "pcap_captures" mkdir pcap_captures

REM Clean up old PCAP files (keep last 5)
echo [1/4] Cleaning old PCAP files (keeping last 5)...
call cleanup_old_pcaps.bat

REM Start honeypot with docker-compose
echo [2/4] Starting Beelzebub Honeypot with Gemini AI...
docker-compose -f docker-compose-simple.yml up -d

REM Wait for services
echo [3/4] Waiting for services to initialize...
timeout /t 5 /nobreak >nul

REM Verify running
echo [4/4] Verifying services...
docker ps --filter "name=beelzebub" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo.
echo ========================================
echo   STATUS
echo ========================================
echo SSH:        localhost:2223
echo HTTP:       localhost:8081
echo MySQL:      localhost:3306
echo PostgreSQL: localhost:5432
echo Logs:       logs\beelzebub.log
echo PCAP:       pcap_captures\honeypot_*.pcap (auto-rotates, keeps last 5)
echo ========================================
echo.
echo [SUCCESS] Honeypot is ready!
echo All traffic will be logged automatically.
echo.
