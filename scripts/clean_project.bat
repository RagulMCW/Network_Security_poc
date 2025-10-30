@echo off
REM Clean Project - Remove Temporary and Unnecessary Files
REM This script removes temporary files, logs, and build artifacts

echo ========================================
echo Network Security POC - Project Cleanup
echo ========================================
echo.
echo This will remove:
echo   - Python cache files (__pycache__, *.pyc)
echo   - Docker build cache
echo   - Old PCAP files (keeps last 5)
echo   - Temporary logs
echo   - Analysis output files
echo.
set /p confirm="Continue? (y/n): "
if /i not "%confirm%"=="y" exit /b

echo.
echo [1/6] Cleaning Python cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc >nul 2>&1
del /s /q *.pyo >nul 2>&1
echo ✓ Python cache cleaned

echo.
echo [2/6] Cleaning old PCAP files...
cd honey_pot\pcap_captures 2>nul
if exist *.pcap (
    for /f "skip=5" %%i in ('dir /b /o-d *.pcap 2^>nul') do del "%%i" >nul 2>&1
    echo ✓ Old PCAP files cleaned (kept last 5)
) else (
    echo ℹ No PCAP files to clean
)
cd ..\..

echo.
echo [3/6] Cleaning network captures...
cd network\captures 2>nul
if exist *.pcap (
    for /f "skip=5" %%i in ('dir /b /o-d *.pcap 2^>nul') do del "%%i" >nul 2>&1
    echo ✓ Old network captures cleaned (kept last 5)
) else (
    echo ℹ No network captures to clean
)
cd ..\..

echo.
echo [4/6] Cleaning temporary files...
del /q network\analyze_output.txt >nul 2>&1
del /q dashboard\*.log >nul 2>&1
del /q honey_pot\captures\* >nul 2>&1
echo ✓ Temporary files cleaned

echo.
echo [5/6] Cleaning Docker build cache...
wsl docker system prune -f >nul 2>&1
echo ✓ Docker cache cleaned

echo.
echo [6/6] Cleaning SSH attacker logs (keeping summary)...
cd attackers\ssh_attacker\logs 2>nul
if exist ssh_attacks_*.log (
    for /f "skip=1" %%i in ('dir /b /o-d ssh_attacks_*.log 2^>nul') do del "%%i" >nul 2>&1
    echo ✓ Old SSH logs cleaned (kept most recent)
) else (
    echo ℹ No SSH logs to clean
)
cd ..\..\..

echo.
echo ========================================
echo Cleanup Complete!
echo ========================================
echo.
echo Project is now clean and optimized.
echo.
pause
