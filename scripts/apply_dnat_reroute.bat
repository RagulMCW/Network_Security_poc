@echo off
echo ========================================
echo Applying DNAT Rerouting for endpoint_behavior_attacker
echo ========================================

set ATTACKER_IP=192.168.6.201
set HONEYPOT_IP=172.18.0.2

echo.
echo Device IP: %ATTACKER_IP%
echo Honeypot IP: %HONEYPOT_IP%
echo.

echo Applying iptables DNAT rules...
echo.

REM HTTP/HTTPS traffic rerouting
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 80 -j DNAT --to-destination %HONEYPOT_IP%:8080
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 443 -j DNAT --to-destination %HONEYPOT_IP%:8080
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 8080 -j DNAT --to-destination %HONEYPOT_IP%:8080
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 5000 -j DNAT --to-destination %HONEYPOT_IP%:8080

REM SSH traffic rerouting
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 22 -j DNAT --to-destination %HONEYPOT_IP%:22

REM Database traffic rerouting
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 3306 -j DNAT --to-destination %HONEYPOT_IP%:3306
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 5432 -j DNAT --to-destination %HONEYPOT_IP%:5432

REM FTP and Telnet rerouting
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 21 -j DNAT --to-destination %HONEYPOT_IP%:21
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 23 -j DNAT --to-destination %HONEYPOT_IP%:23

echo.
echo Applying FORWARD rules...
echo.

REM Allow traffic from attacker to honeypot
wsl sudo iptables -A FORWARD -s %ATTACKER_IP% -d %HONEYPOT_IP% -j ACCEPT

REM Allow return traffic from honeypot to attacker
wsl sudo iptables -A FORWARD -s %HONEYPOT_IP% -d %ATTACKER_IP% -j ACCEPT

echo.
echo Applying MASQUERADE rule...
echo.

REM MASQUERADE for return traffic
wsl sudo iptables -t nat -A POSTROUTING -s %ATTACKER_IP% -d %HONEYPOT_IP% -j MASQUERADE

echo.
echo ========================================
echo ✅ DNAT REROUTING APPLIED SUCCESSFULLY!
echo ========================================
echo.
echo Verifying iptables rules...
echo.
wsl sudo iptables -t nat -L PREROUTING -n -v --line-numbers | findstr /C:"%ATTACKER_IP%"
echo.
echo All traffic from %ATTACKER_IP% is now rerouted to honeypot!
echo.
pause
