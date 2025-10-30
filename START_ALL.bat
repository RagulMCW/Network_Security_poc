@echo off
REM Start All Network Security POC Services
REM This will start everything in the correct order with proper ports

echo ========================================
echo STARTING ALL SERVICES
echo ========================================
echo.
echo This will start:
echo   1. Network Monitor (192.168.6.131:5000) - Flask API
echo   2. Beelzebub Honeypot (172.18.0.2:22/8080/3306/5432)
echo   3. PCAP Capture
echo   4. Dashboard (localhost:5100) - Web UI
echo.
pause

echo.
echo [1/4] Starting Network Monitor...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/network && docker compose up -d"
echo Waiting 10 seconds for network monitor to initialize...
timeout /t 10 /nobreak >nul

echo.
echo [2/4] Starting Beelzebub Honeypot...
wsl bash -c "cd /mnt/e/nos/Network_Security_poc/honey_pot && docker compose -f docker-compose-simple.yml up -d"
echo Waiting 5 seconds for honeypot to start...
timeout /t 5 /nobreak >nul

echo.
echo [3/4] Verifying Services...
echo.
echo Docker Containers:
wsl docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo.
echo [4/4] Starting Dashboard...
echo Dashboard will open in a new window on http://localhost:5100
echo.
start "" cmd /k "cd /d E:\nos\Network_Security_poc\dashboard && E:\nos\.venv\Scripts\activate.bat && python app.py"

timeout /t 3 /nobreak >nul
start http://localhost:5100

echo.
echo ========================================
echo ALL SERVICES STARTED!
echo ========================================
echo.
echo Access Points:
echo   📊 Dashboard:        http://localhost:5100
echo   🌐 Network Monitor:  http://192.168.6.131:5000
echo   🍯 Honeypot Web:     http://172.18.0.2:8080
echo   📈 HAProxy Stats:    http://localhost:8404
echo.
echo To start attackers:
echo   - DOS Attacker:  Use dashboard or run attackers/dos_attacker/START_DOS.bat
echo   - SSH Attacker:  Use dashboard or run attackers/ssh_attacker/START_SSH_ATTACKER.bat
echo.
echo Press any key to continue...
pause >nul
