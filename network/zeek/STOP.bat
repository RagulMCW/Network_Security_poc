@echo off
REM Zeek Network Monitor - Stop Script
REM Terminates all monitoring processes

title Stopping Zeek Monitor

echo.
echo ================================================
echo    Zeek Network Monitor - Stopping
echo ================================================
echo.

wsl bash -c "sudo pkill -f zeek_monitor; sudo pkill -f 'tcpdump.*br-'; tmux kill-session -t zeek_monitor 2>/dev/null; exit 0"

timeout /t 2 >nul

echo.
echo Monitor stopped
echo Logs preserved in zeek_logs folder
echo.
