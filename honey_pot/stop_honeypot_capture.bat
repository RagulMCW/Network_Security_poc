@echo off
REM Stop Beelzebub Honeypot Packet Capture

echo ========================================
echo Stopping Honeypot Capture
echo ========================================
echo.

wsl bash -c "sudo pkill -f 'tcpdump.*honeypot_net' && echo 'Honeypot capture stopped' || echo 'No capture running'"

echo.
echo Recent honeypot capture files:
wsl bash -c "ls -lth /mnt/e/nos/Network_Security_poc/honey_pot/pcap_captures/*.pcap 2>/dev/null | head -5"
