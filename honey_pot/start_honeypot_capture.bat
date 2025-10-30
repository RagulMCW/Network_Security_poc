@echo off
REM Start Beelzebub Honeypot Packet Capture
REM This captures all traffic on honeypot_net including redirected attacks

echo ========================================
echo Starting Beelzebub Honeypot Capture
echo ========================================
echo.

wsl bash /mnt/e/nos/Network_Security_poc/honey_pot/capture_honeypot_traffic.sh
