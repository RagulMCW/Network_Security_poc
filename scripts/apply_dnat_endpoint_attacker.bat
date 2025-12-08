@echo off
REM ============================================================
REM Apply DNAT Rerouting for endpoint_behavior_attacker
REM This reroutes ALL traffic (9 ports) to Beelzebub honeypot
REM ============================================================

set ATTACKER_IP=192.168.6.201
set HONEYPOT_IP=172.18.0.2

echo.
echo ============================================================
echo Applying DNAT iptables rules for endpoint_behavior_attacker
echo ============================================================
echo   Source IP: %ATTACKER_IP%
echo   Honeypot IP: %HONEYPOT_IP%
echo ============================================================
echo.

REM DNAT rules for ALL traffic - 9 ports
echo [1/9] Rerouting HTTP (port 80)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 80 -j DNAT --to-destination %HONEYPOT_IP%:8080

echo [2/9] Rerouting HTTPS (port 443)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 443 -j DNAT --to-destination %HONEYPOT_IP%:8080

echo [3/9] Rerouting HTTP-ALT (port 8080)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 8080 -j DNAT --to-destination %HONEYPOT_IP%:8080

echo [4/9] Rerouting Flask API (port 5000)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 5000 -j DNAT --to-destination %HONEYPOT_IP%:8080

echo [5/9] Rerouting SSH (port 22)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 22 -j DNAT --to-destination %HONEYPOT_IP%:22

echo [6/9] Rerouting MySQL (port 3306)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 3306 -j DNAT --to-destination %HONEYPOT_IP%:3306

echo [7/9] Rerouting PostgreSQL (port 5432)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 5432 -j DNAT --to-destination %HONEYPOT_IP%:5432

echo [8/9] Rerouting FTP (port 21)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 21 -j DNAT --to-destination %HONEYPOT_IP%:21

echo [9/9] Rerouting Telnet (port 23)...
wsl sudo iptables -t nat -A PREROUTING -s %ATTACKER_IP% -p tcp --dport 23 -j DNAT --to-destination %HONEYPOT_IP%:23

echo.
echo ============================================================
echo Adding FORWARD rules for bidirectional traffic...
echo ============================================================

echo [1/2] Allow traffic from attacker to honeypot...
wsl sudo iptables -A FORWARD -s %ATTACKER_IP% -d %HONEYPOT_IP% -j ACCEPT

echo [2/2] Allow return traffic from honeypot to attacker...
wsl sudo iptables -A FORWARD -s %HONEYPOT_IP% -d %ATTACKER_IP% -j ACCEPT

echo.
echo ============================================================
echo Adding MASQUERADE rule for source NAT...
echo ============================================================
wsl sudo iptables -t nat -A POSTROUTING -s %ATTACKER_IP% -d %HONEYPOT_IP% -j MASQUERADE

echo.
echo ============================================================
echo VERIFICATION: Current DNAT rules
echo ============================================================
wsl sudo iptables -t nat -L PREROUTING -n -v --line-numbers | findstr %ATTACKER_IP%

echo.
echo ============================================================
echo SUCCESS: All DNAT rules applied!
echo ============================================================
echo   Device: endpoint_behavior_attacker (%ATTACKER_IP%)
echo   Honeypot: Beelzebub (%HONEYPOT_IP%)
echo   Rules: 12 total (9 DNAT + 2 FORWARD + 1 MASQUERADE)
echo   Method: Traffic rerouting only - device stays on custom_net
echo ============================================================
echo.
pause
