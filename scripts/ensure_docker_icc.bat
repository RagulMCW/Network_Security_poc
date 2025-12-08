@echo off
REM ============================================
REM Ensure Docker Inter-Container Communication
REM ============================================
REM This script ensures that containers on custom_net can communicate with each other
REM Critical for devices to reach network-monitor server

echo.
echo ========================================
echo   ENSURING DOCKER ICC RULE
echo ========================================
echo.

REM Get custom_net bridge ID
for /f %%i in ('wsl bash -c "docker network inspect custom_net --format '{{.Id}}' 2>/dev/null | cut -c1-12"') do set BRIDGE_ID=%%i

if "%BRIDGE_ID%"=="" (
    echo [ERROR] Could not get custom_net bridge ID. Is Docker running?
    pause
    exit /b 1
)

set BRIDGE_NAME=br-%BRIDGE_ID%
echo [INFO] Custom_net bridge: %BRIDGE_NAME%

REM Check if ICC rule exists, if not add it
echo [INFO] Checking inter-container communication rule...
wsl bash -c "sudo iptables -C FORWARD -i %BRIDGE_NAME% -o %BRIDGE_NAME% -j ACCEPT 2>/dev/null"

if %ERRORLEVEL% NEQ 0 (
    echo [INFO] ICC rule not found, adding it...
    wsl bash -c "sudo iptables -I FORWARD 1 -i %BRIDGE_NAME% -o %BRIDGE_NAME% -j ACCEPT"
    if %ERRORLEVEL% EQU 0 (
        echo [SUCCESS] Inter-container communication rule added
    ) else (
        echo [ERROR] Failed to add ICC rule
        pause
        exit /b 1
    )
) else (
    echo [SUCCESS] ICC rule already exists
)

REM Also add subnet-based rule as backup
echo [INFO] Adding subnet-based ICC rule...
wsl bash -c "sudo iptables -C FORWARD -s 192.168.6.0/24 -d 192.168.6.0/24 -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -s 192.168.6.0/24 -d 192.168.6.0/24 -j ACCEPT"

echo.
echo [SUCCESS] Docker inter-container communication ensured!
echo.
echo Current FORWARD rules:
wsl bash -c "sudo iptables -L FORWARD -n -v --line-numbers | head -10"
echo.
pause
