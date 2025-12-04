@echo off
REM Cleanup old PCAP files - keep only last 5
echo Cleaning up old PCAP files...
echo Keeping only the 5 most recent captures

cd /d "%~dp0pcap_captures"

REM Count PCAP files
set count=0
for %%f in (honeypot_*.pcap) do set /a count+=1

echo Found %count% PCAP files

if %count% LEQ 5 (
    echo No cleanup needed. Files: %count%/5
    exit /b 0
)

REM Delete oldest files, keep last 5
echo Deleting old PCAP files...
wsl bash -c "cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/honey_pot/pcap_captures && ls -t honeypot_*.pcap | tail -n +6 | xargs -r rm -fv"

echo Cleanup complete!
echo Remaining files:
dir /b honeypot_*.pcap 2>nul
