@echo off
REM View PCAP captures
echo ========================================
echo   HONEYPOT PACKET CAPTURES
echo ========================================
echo.

cd /d "%~dp0pcap_captures"

REM Count files
set count=0
for %%f in (honeypot_*.pcap) do set /a count+=1

if %count% EQU 0 (
    echo No PCAP files found.
    echo Start the honeypot to begin capturing traffic.
    echo.
    pause
    exit /b 0
)

echo Found %count% PCAP file(s):
echo.

REM List files with details
dir /od honeypot_*.pcap 2>nul

echo.
echo ========================================
echo   ACTIONS
echo ========================================
echo 1. Open folder in Explorer
echo 2. Analyze with Wireshark (if installed)
echo 3. Show file sizes
echo 4. Delete all PCAP files
echo 5. Exit
echo.

set /p choice="Enter choice (1-5): "

if "%choice%"=="1" goto open_folder
if "%choice%"=="2" goto wireshark
if "%choice%"=="3" goto show_sizes
if "%choice%"=="4" goto delete_all
if "%choice%"=="5" goto :EOF

:open_folder
explorer .
goto :EOF

:wireshark
echo.
echo Opening most recent PCAP in Wireshark...
for /f "delims=" %%f in ('dir /b /od honeypot_*.pcap 2^>nul') do set latest=%%f
if exist "%latest%" (
    echo Opening: %latest%
    start "" "%latest%"
) else (
    echo No PCAP files found
)
pause
goto :EOF

:show_sizes
echo.
echo File sizes:
for %%f in (honeypot_*.pcap) do (
    echo %%~zf bytes - %%f
)
echo.
pause
goto :EOF

:delete_all
echo.
echo WARNING: This will delete ALL PCAP files!
set /p confirm="Are you sure? (y/n): "
if /i "%confirm%"=="y" (
    del /q honeypot_*.pcap 2>nul
    echo All PCAP files deleted.
) else (
    echo Cancelled.
)
pause
goto :EOF
