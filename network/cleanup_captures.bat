@echo off
REM Cleanup Old Capture Files
REM Keeps only the most recent N capture files
REM Usage: cleanup_captures.bat [count]
REM Example: cleanup_captures.bat 5
REM ========================================

setlocal

REM Get keep count from argument (default to 5)
set KEEP_COUNT=%1
if "%KEEP_COUNT%"=="" set KEEP_COUNT=5

echo ========================================
echo Capture Files Cleanup
echo ========================================
echo Keeping last %KEEP_COUNT% files...
echo.

REM Activate virtual environment
call E:\nos\.venv\Scripts\activate.bat 2>nul
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    exit /b 1
)

REM Navigate to network directory
cd /d E:\nos\Network_Security_poc\network

REM Run cleanup
python scripts\analyze_capture.py --cleanup --keep %KEEP_COUNT%

REM Deactivate
call deactivate 2>nul

echo.
echo Done!
pause
