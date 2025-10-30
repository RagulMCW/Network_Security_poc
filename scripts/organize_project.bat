@echo off
REM Professional File Organization Script
REM This script reorganizes the project structure for a clean, professional layout

echo ========================================
echo Network Security POC - File Organization
echo ========================================
echo.
echo This will:
echo   1. Move documentation to docs/ folder
echo   2. Move utility scripts to scripts/ folder
echo   3. Remove unused/redundant files
echo   4. Create clean folder structure
echo.
pause

echo.
echo [1/5] Creating professional folder structure...

REM Create main directories
if not exist "docs" mkdir docs
if not exist "scripts" mkdir scripts
if not exist "logs" mkdir logs

echo.
echo [2/5] Moving documentation files...

REM Move documentation to docs/
if exist "SSH_SETUP_GUIDE.md" move "SSH_SETUP_GUIDE.md" "docs\" >nul 2>&1
if exist "SYSTEM_SUMMARY.md" move "SYSTEM_SUMMARY.md" "docs\" >nul 2>&1
if exist "flow.md" move "flow.md" "docs\" >nul 2>&1
if exist "dummy.md" del "dummy.md" >nul 2>&1

REM Move troubleshooting docs
if exist "dashboard\TROUBLESHOOTING.md" move "dashboard\TROUBLESHOOTING.md" "docs\" >nul 2>&1
if exist "dashboard\fix_firewall.bat" move "dashboard\fix_firewall.bat" "scripts\" >nul 2>&1
if exist "dashboard\fix_port_conflict.bat" move "dashboard\fix_port_conflict.bat" "scripts\" >nul 2>&1
if exist "dashboard\diagnose.bat" move "dashboard\diagnose.bat" "scripts\" >nul 2>&1

echo.
echo [3/5] Moving utility scripts...

REM Move scripts to scripts/
if exist "test_system.bat" move "test_system.bat" "scripts\" >nul 2>&1
if exist "test_system.sh" move "test_system.sh" "scripts\" >nul 2>&1
if exist "start_all.sh" move "start_all.sh" "scripts\" >nul 2>&1
if exist "dashboard\setup_passwordless_iptables.bat" move "dashboard\setup_passwordless_iptables.bat" "scripts\" >nul 2>&1
if exist "dashboard\apply_iptables_reroute.bat" move "dashboard\apply_iptables_reroute.bat" "scripts\" >nul 2>&1

echo.
echo [4/5] Cleaning up redundant files...

REM Remove old/unused scripts
if exist "dashboard\start_dashboard_wsl.bat" del "dashboard\start_dashboard_wsl.bat" >nul 2>&1
if exist "dashboard\complete_setup.bat" move "dashboard\complete_setup.bat" "scripts\initial_setup.bat" >nul 2>&1

REM Clean honeypot folder
if exist "honey_pot\monitor_status.bat" del "honey_pot\monitor_status.bat" >nul 2>&1
if exist "honey_pot\monitor_status.sh" del "honey_pot\monitor_status.sh" >nul 2>&1
if exist "honey_pot\capture_honeypot_traffic.sh" del "honey_pot\capture_honeypot_traffic.sh" >nul 2>&1
if exist "honey_pot\log_network_attacks.sh" del "honey_pot\log_network_attacks.sh" >nul 2>&1
if exist "honey_pot\monitor_honeypot_traffic.py" del "honey_pot\monitor_honeypot_traffic.py" >nul 2>&1
if exist "honey_pot\QUICK_REFERENCE.md" move "honey_pot\QUICK_REFERENCE.md" "docs\HONEYPOT_REFERENCE.md" >nul 2>&1

REM Clean network folder
if exist "network\analyze_auto.bat" del "network\analyze_auto.bat" >nul 2>&1
if exist "network\analyze.bat" del "network\analyze.bat" >nul 2>&1
if exist "network\run_analyze_auto.py" del "network\run_analyze_auto.py" >nul 2>&1
if exist "network\analyze_output.txt" del "network\analyze_output.txt" >nul 2>&1
if exist "network\network-monitor.html" del "network\network-monitor.html" >nul 2>&1

echo.
echo [5/5] Creating professional README...

REM The main README will be updated separately

echo.
echo ========================================
echo Organization Complete!
echo ========================================
echo.
echo New Structure:
echo   docs/           - All documentation
echo   scripts/        - Utility scripts
echo   logs/           - System logs (gitignored)
echo   attackers/      - Attack simulators
echo   dashboard/      - Web dashboard
echo   honey_pot/      - Honeypot services
echo   mcp_agent/      - AI agent
echo   network/        - Network monitoring
echo   devices/        - Device simulation
echo.
echo Removed:
echo   - Redundant batch files
echo   - Unused monitoring scripts
echo   - Test/debug files
echo   - Duplicate documentation
echo.
pause
