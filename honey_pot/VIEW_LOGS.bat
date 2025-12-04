@echo off
REM ============================================
REM View Honeypot Logs by Service Type
REM ============================================

cd /d "%~dp0"

:menu
cls
echo.
echo ========================================
echo   HONEYPOT LOGS VIEWER
echo ========================================
echo.
echo 1. View All Logs (beelzebub.log)
echo 2. View SSH Attacks Only
echo 3. View HTTP Attacks Only
echo 4. View MySQL Attacks Only
echo 5. View PostgreSQL Attacks Only
echo 6. View LLM AI Responses Only
echo 7. View Live Logs (Real-time)
echo 8. Count Total Attacks
echo 9. Exit
echo.
set /p choice="Select option: "

if "%choice%"=="1" goto all_logs
if "%choice%"=="2" goto ssh_logs
if "%choice%"=="3" goto http_logs
if "%choice%"=="4" goto mysql_logs
if "%choice%"=="5" goto postgres_logs
if "%choice%"=="6" goto llm_logs
if "%choice%"=="7" goto live_logs
if "%choice%"=="8" goto count_attacks
if "%choice%"=="9" goto :EOF

:all_logs
cls
echo Viewing: logs\beelzebub.log
echo.
type logs\beelzebub.log
pause
goto menu

:ssh_logs
cls
echo Extracting SSH attacks (port 22)...
wsl bash -c "grep 'SSH Raw Command' logs/beelzebub.log | tail -20" 2>nul
if %ERRORLEVEL% NEQ 0 (
    findstr /i "ssh" logs\beelzebub.log 2>nul
)
pause
goto menu

:http_logs
cls
echo Extracting HTTP attacks (port 80)...
wsl bash -c "grep -i 'http' logs/beelzebub.log | tail -20" 2>nul
if %ERRORLEVEL% NEQ 0 (
    findstr /i "http" logs\beelzebub.log 2>nul
)
pause
goto menu

:mysql_logs
cls
echo Extracting MySQL attacks (port 3306)...
wsl bash -c "grep -i 'mysql\|3306' logs/beelzebub.log | tail -20" 2>nul
if %ERRORLEVEL% NEQ 0 (
    findstr /i "mysql 3306" logs\beelzebub.log 2>nul
)
pause
goto menu

:postgres_logs
cls
echo Extracting PostgreSQL attacks (port 5432)...
wsl bash -c "grep -i 'postgres\|5432' logs/beelzebub.log | tail -20" 2>nul
if %ERRORLEVEL% NEQ 0 (
    findstr /i "postgres 5432" logs\beelzebub.log 2>nul
)
pause
goto menu

:llm_logs
cls
echo Extracting LLM AI Responses...
echo.
python extract_llm_logs.py
echo.
echo Opening LLM responses log...
notepad logs\llm_responses.jsonl
goto menu

:live_logs
cls
echo Viewing live logs (Ctrl+C to stop)...
echo.
docker logs -f beelzebub-honeypot
goto menu

:count_attacks
cls
echo.
echo ========================================
echo   ATTACK STATISTICS
echo ========================================
echo.
wsl bash -c "echo 'Total SSH Commands:' && grep -c 'SSH Raw Command' logs/beelzebub.log 2>/dev/null || echo 0" 2>nul
wsl bash -c "echo 'Total Login Attempts:' && grep -c 'SSH Login Attempt' logs/beelzebub.log 2>/dev/null || echo 0" 2>nul
wsl bash -c "echo 'Unique IPs:' && grep 'SourceIp' logs/beelzebub.log | grep -oP '\"SourceIp\":\"[^\"]+\"' | sort -u | wc -l 2>/dev/null || echo 0" 2>nul
echo.
pause
goto menu
