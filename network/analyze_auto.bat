@echo off
setlocal enabledelayedexpansion
REM Automated Analysis Script (Non-Interactive)
REM Usage: analyze_auto.bat [latest|all]
REM ========================================

REM Get mode from argument (default to "latest")
set MODE=%1
if "%MODE%"=="" set MODE=latest

REM Activate virtual environment quietly
call E:\nos\.venv\Scripts\activate.bat 2>nul
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    exit /b 1
)

REM Navigate to network directory
cd /d E:\nos\Network_Security_poc\network

REM Check if captures exist
if not exist "captures\*.pcap*" (
    echo ERROR: No capture files found
    exit /b 1
)

REM Auto-cleanup: Keep only last 5 captures (silent mode)
python scripts\analyze_capture.py --cleanup --keep 5 --silent

REM Execute based on mode
if /i "%MODE%"=="latest" goto :analyze_latest
if /i "%MODE%"=="all" goto :analyze_all
echo ERROR: Invalid mode "%MODE%" (use "latest" or "all")
exit /b 1

:analyze_latest
echo Analyzing latest capture...
for /f "delims=" %%f in ('dir /b /o-d /tc captures\*.pcap* 2^>nul') do (
    echo File: %%f
    python scripts\analyze_capture.py "captures\%%f"
    goto :cleanup
)
echo ERROR: No capture files found
exit /b 1

:analyze_all
echo Analyzing last 5 captures...
set count=0
for /f "delims=" %%f in ('dir /b /o-d /tc captures\*.pcap* 2^>nul') do (
    set /a count+=1
    if !count! leq 5 (
        echo.
        echo === %%f ===
        python scripts\analyze_capture.py "captures\%%f"
    )
)
goto :cleanup

:cleanup
call deactivate 2>nul
exit /b 0
