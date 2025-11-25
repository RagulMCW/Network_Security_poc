@echo off
echo Starting Extracted Files Cleanup Service...
echo Keeping only the last 5 files in zeek_logs/extracted_files
echo.

REM Check if python is available
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Python not found! Please ensure Python is installed and in PATH.
    pause
    exit /b
)

python "%~dp0cleanup_extracted_files.py"
pause