@echo off
REM Cleanup Old Capture Files
REM Keeps only the most recent 4 capture files automatically
REM Usage: cleanup_captures.bat
REM ========================================

setlocal

set KEEP_COUNT=4

echo ========================================
echo Capture Files Cleanup
echo ========================================
echo Keeping last %KEEP_COUNT% files only...
echo.

REM Use WSL to clean up PCAP files
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/network/captures && echo 'Current PCAP files:' && ls -1t *.pcap 2>/dev/null | head -10 && echo '' && TOTAL=$(ls -1 *.pcap 2>/dev/null | wc -l) && echo \"Total files: ${TOTAL}\" && if [ ${TOTAL} -gt %KEEP_COUNT% ]; then echo 'Deleting old files...' && ls -1t *.pcap | tail -n +5 | xargs rm -f && echo \"Deleted $((TOTAL - %KEEP_COUNT%)) old files\"; else echo 'No cleanup needed'; fi && echo '' && echo 'Remaining files:' && ls -lh *.pcap 2>/dev/null"

echo.
echo ========================================
echo Cleanup Complete!
echo ========================================
pause
