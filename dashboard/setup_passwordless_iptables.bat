@echo off
echo ==========================================
echo Setup Passwordless Sudo for iptables
echo ==========================================
echo.
echo This will configure WSL to allow iptables
echo commands without password prompts.
echo.
echo You will be asked for your password ONCE.
echo After that, auto-isolation will work without
echo any password prompts.
echo.
pause

cd /d %~dp0
wsl bash setup_passwordless_iptables.sh

echo.
echo ==========================================
echo Done!
echo ==========================================
echo.
pause
