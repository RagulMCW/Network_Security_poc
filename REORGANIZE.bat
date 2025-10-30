@echo off
REM Move files to proper locations

cd /d E:\nos\Network_Security_poc

echo Moving documentation files...
if exist SSH_SETUP_GUIDE.md move SSH_SETUP_GUIDE.md docs\
if exist SYSTEM_SUMMARY.md move SYSTEM_SUMMARY.md docs\
if exist flow.md move flow.md docs\
if exist dashboard\TROUBLESHOOTING.md move dashboard\TROUBLESHOOTING.md docs\
if exist dummy.md del dummy.md

echo Moving utility scripts...
if exist test_system.bat move test_system.bat scripts\
if exist test_system.sh move test_system.sh scripts\
if exist start_all.sh move start_all.sh scripts\

echo Cleaning up dashboard folder...
if exist dashboard\setup_passwordless_iptables.bat move dashboard\setup_passwordless_iptables.bat scripts\
if exist dashboard\apply_iptables_reroute.bat move dashboard\apply_iptables_reroute.bat scripts\
if exist dashboard\fix_firewall.bat move dashboard\fix_firewall.bat scripts\
if exist dashboard\fix_port_conflict.bat move dashboard\fix_port_conflict.bat scripts\
if exist dashboard\diagnose.bat move dashboard\diagnose.bat scripts\
if exist dashboard\complete_setup.bat move dashboard\complete_setup.bat scripts\initial_setup.bat
if exist dashboard\start_dashboard_wsl.bat del dashboard\start_dashboard_wsl.bat

echo Cleaning up honeypot folder...
if exist honey_pot\monitor_status.bat del honey_pot\monitor_status.bat
if exist honey_pot\monitor_status.sh del honey_pot\monitor_status.sh
if exist honey_pot\capture_honeypot_traffic.sh del honey_pot\capture_honeypot_traffic.sh
if exist honey_pot\log_network_attacks.sh del honey_pot\log_network_attacks.sh
if exist honey_pot\monitor_honeypot_traffic.py del honey_pot\monitor_honeypot_traffic.py
if exist honey_pot\QUICK_REFERENCE.md move honey_pot\QUICK_REFERENCE.md docs\HONEYPOT_REFERENCE.md

echo Cleaning up network folder...
if exist network\analyze_auto.bat del network\analyze_auto.bat
if exist network\analyze.bat del network\analyze.bat
if exist network\run_analyze_auto.py del network\run_analyze_auto.py
if exist network\analyze_output.txt del network\analyze_output.txt
if exist network\network-monitor.html del network\network-monitor.html

echo Done!
pause
