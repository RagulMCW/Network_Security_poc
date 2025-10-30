@echo off
REM Start host-based packet capture on WSL
REM This captures ALL traffic on custom_net Docker bridge

echo ========================================
echo STARTING HOST-BASED PACKET CAPTURE
echo ========================================
echo.
echo This will capture ALL traffic on custom_net including:
echo   - DoS attacks from hping3-attacker
echo   - Device telemetry
echo   - All network activity
echo.
echo Press Ctrl+C in the WSL window to stop
echo.

cd /d E:\nos\Network_Security_poc\network\scripts

wsl bash capture_on_host.sh

pause
