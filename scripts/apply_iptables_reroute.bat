@echo off
REM Apply iptables rules to reroute attacker traffic to honeypot
REM Usage: apply_iptables_reroute.bat [device_ip]

set DEVICE_IP=%1
if "%DEVICE_IP%"=="" set DEVICE_IP=192.168.6.132

set HONEYPOT_IP=192.168.7.3

echo ====================================
echo Traffic Rerouting via iptables
echo ====================================
echo Device IP: %DEVICE_IP%
echo Honeypot Target: %HONEYPOT_IP%
echo.

echo [1/3] Adding TCP DNAT rule...
wsl bash -c "sudo iptables -t nat -A PREROUTING -s %DEVICE_IP% -p tcp -j DNAT --to-destination %HONEYPOT_IP%"
echo   Done

echo.
echo [2/3] Adding UDP DNAT rule...
wsl bash -c "sudo iptables -t nat -A PREROUTING -s %DEVICE_IP% -p udp -j DNAT --to-destination %HONEYPOT_IP%"
echo   Done

echo.
echo [3/3] Adding packet marking rule...
wsl bash -c "sudo iptables -t mangle -A PREROUTING -s %DEVICE_IP% -j MARK --set-mark 100"
echo   Done

echo.
echo ====================================
echo Traffic rerouting configured!
echo.
echo All packets from %DEVICE_IP% will be redirected to %HONEYPOT_IP%
echo ====================================
echo.

pause
