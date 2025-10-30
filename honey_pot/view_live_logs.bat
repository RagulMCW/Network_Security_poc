@echo off
echo ==========================================
echo Beelzebub Honeypot - Live Logs
echo ==========================================
echo.
echo Showing real-time logs from Beelzebub...
echo Press Ctrl+C to stop
echo.
echo ==========================================
echo.

wsl tail -f /mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log
