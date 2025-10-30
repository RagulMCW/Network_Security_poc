@echo off
REM Stop host-based packet capture

echo Stopping packet capture...

wsl bash /mnt/e/nos/Network_Security_poc/network/scripts/stop_capture.sh

echo.
pause
