@echo off
echo ==========================================
echo Complete Auto-Rerouting Setup
echo ==========================================
echo.
echo This will:
echo   1. Configure passwordless sudo (password: ragul)
echo   2. Connect Beelzebub to honeypot network
echo   3. Connect all devices to honeypot network
echo   4. Apply iptables rules for traffic rerouting
echo   5. Enable automatic logging to Beelzebub
echo.
echo You will be asked for password ONCE.
echo After that, everything works automatically!
echo.
pause

cd /d %~dp0
wsl bash complete_setup.sh

echo.
echo ==========================================
echo Setup Complete!
echo ==========================================
echo.
echo Auto-rerouting is now active.
echo All device traffic goes to Beelzebub honeypot.
echo.
echo View logs:
echo   wsl tail -f /mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log
echo.
pause
