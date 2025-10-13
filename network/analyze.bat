@echo off
REM Quick Analysis Script for Windows
REM Uses virtual environment at E:\nos\.venv
REM ========================================

echo.
echo ========================================
echo Network Security Monitor - Analyzer
echo ========================================
echo.

REM Activate virtual environment
echo Activating Python virtual environment...
call E:\nos\.venv\Scripts\activate.bat

if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    echo Make sure E:\nos\.venv exists
    pause
    exit /b 1
)

echo SUCCESS: Virtual environment activated
echo.

REM Navigate to project
cd /d E:\nos\Network_Security_poc\network

REM Check if captures exist
if not exist "captures\*.pcap*" (
    echo WARNING: No capture files found in captures directory
    echo Make sure Docker container is running and capturing data
    echo.
    pause
    goto :cleanup
)

REM Show available captures
echo Available capture files:
echo ========================
dir /b captures\*.pcap* 2>nul
echo.

REM Ask user what to analyze
echo.
echo What would you like to do?
echo 1. Analyze LATEST capture only (recommended)
echo 2. Analyze all captures
echo 3. Analyze specific file
echo 4. Just list files
echo 5. Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto :analyze_latest
if "%choice%"=="2" goto :analyze_all
if "%choice%"=="3" goto :analyze_specific
if "%choice%"=="4" goto :list_files
if "%choice%"=="5" goto :cleanup
echo Invalid choice
goto :cleanup

:analyze_latest
echo.
echo Analyzing LATEST capture only...
echo ========================================
REM Get the newest file by sorting by date modified
for /f "delims=" %%f in ('dir /b /o-d /tc captures\*.pcap* 2^>nul') do (
    echo.
    echo Latest file: %%f
    echo Created: 
    dir captures\%%f | find "/"
    echo.
    python scripts\analyze_capture.py "captures\%%f"
    goto :done
)
echo No capture files found
goto :done

:analyze_all
echo.
echo Analyzing ALL capture files...
echo ========================================
for %%f in (captures\*.pcap*) do (
    echo.
    echo --- Analyzing: %%f ---
    python scripts\analyze_capture.py "%%f"
    echo.
)
goto :done

:analyze_specific
echo.
echo Enter filename (e.g., capture.pcap):
set /p filename="Filename: "
if exist "captures\%filename%" (
    python scripts\analyze_capture.py "captures\%filename%"
) else (
    echo ERROR: File not found: captures\%filename%
)
goto :done

:list_files
echo.
echo Detailed file information:
echo ========================
dir captures\*.pcap* 2>nul
goto :done

:done
echo.
echo ========================================
echo Analysis complete!
echo ========================================
pause

:cleanup
echo.
echo Deactivating virtual environment...
call deactivate
echo Done.
echo.
