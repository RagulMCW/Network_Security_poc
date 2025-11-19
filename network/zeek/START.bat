@echo off
REM Zeek Network Monitor - Start Script
REM Launches continuous network traffic monitoring

title Zeek Network Monitor

echo.
echo ================================================
echo    Zeek Network Monitor - Starting
echo ================================================
echo.
echo Network: custom_net
echo Output:  zeek_logs\
echo Interval: 2-3 seconds
echo.
echo A new window will open with the monitor running.
echo Keep that window open to continue monitoring.
echo.
echo To stop: Close the monitor window or press Ctrl+C
echo.
echo ================================================
echo.

start "Zeek Network Monitor" wsl sudo bash /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/network/zeek/zeek_monitor.sh

timeout /t 2 >nul
echo Monitor started successfully
echo Check zeek_logs folder for output
echo.
