@echo off
REM Virtual Device Manager for Windows
REM Creates and manages multiple virtual devices on the Docker network

setlocal enabledelayedexpansion

set "NETWORK_NAME=custom_net"
set "DEVICE_IMAGE=virtual-device:latest"
set "DEVICE_BASE_IP=192.168.6"
set "DEVICE_START_IP=10"
set "DEVICE_CONTAINER_PREFIX=vdevice"

:main
if "%1"=="" goto show_usage
if /i "%1"=="build" goto build_image
if /i "%1"=="create" goto create_devices
if /i "%1"=="list" goto list_devices
if /i "%1"=="start" goto start_devices
if /i "%1"=="stop" goto stop_devices
if /i "%1"=="remove" goto remove_devices
if /i "%1"=="logs" goto view_logs
if /i "%1"=="stats" goto show_stats
if /i "%1"=="help" goto show_usage
if /i "%1"=="-h" goto show_usage
if /i "%1"=="--help" goto show_usage

echo [ERROR] Unknown command: %1
echo.
goto show_usage

:build_image
echo ========================================
echo   Building Device Docker Image
echo ========================================
cd /d "%~dp0"

if not exist "Dockerfile" (
    echo [ERROR] Dockerfile not found in devices directory
    exit /b 1
)

echo [INFO] Building image: %DEVICE_IMAGE%
wsl docker build -t %DEVICE_IMAGE% .

if %errorlevel% equ 0 (
    echo [SUCCESS] Device image built successfully
) else (
    echo [ERROR] Failed to build device image
    exit /b 1
)
goto :eof

:create_devices
set "count=%2"
set "device_type=%3"
if "%device_type%"=="" set "device_type=generic"

if "%count%"=="" (
    echo [ERROR] Please specify number of devices to create
    echo Usage: %~nx0 create ^<count^> [device_type]
    echo Device types: iot_sensor, smartphone, laptop, camera, generic
    exit /b 1
)

echo ========================================
echo   Creating Virtual Devices
echo ========================================
echo [INFO] Creating %count% devices (type: %device_type%)

REM Check if image exists
wsl docker image inspect %DEVICE_IMAGE% >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Device image not found. Building...
    call :build_image
)

REM Check if network exists
wsl docker network inspect %NETWORK_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Network '%NETWORK_NAME%' not found. Please start the main server first.
    exit /b 1
)

REM Create devices
for /l %%i in (1,1,%count%) do (
    set "device_num=00%%i"
    set "device_num=!device_num:~-3!"
    set "device_id=device_!device_num!"
    set "container_name=%DEVICE_CONTAINER_PREFIX%_!device_num!"
    set /a ip_offset=%%i-1
    set /a ip_last=%DEVICE_START_IP%+!ip_offset!
    set "ip_address=%DEVICE_BASE_IP%.!ip_last!"
    
    REM Check if container exists
    wsl docker ps -a --format "{{.Names}}" | findstr /x "!container_name!" >nul 2>&1
    if !errorlevel! equ 0 (
        echo [INFO] Device !device_id! already exists ^(!container_name!^)
    ) else (
        echo [INFO] Creating !device_id! at !ip_address!
        
        wsl docker run -d --name "!container_name!" --network "%NETWORK_NAME%" --ip "!ip_address!" -e DEVICE_ID="!device_id!" -e DEVICE_TYPE="%device_type%" -e SERVER_URL="http://192.168.6.131:5000" -e REQUEST_INTERVAL="5" --restart unless-stopped "%DEVICE_IMAGE%" >nul 2>&1
        
        if !errorlevel! equ 0 (
            echo [SUCCESS] Created device: !device_id! at !ip_address!
        ) else (
            echo [ERROR] Failed to create device: !device_id!
        )
        
        timeout /t 1 /nobreak >nul
    )
)

echo.
echo [SUCCESS] Device creation completed
echo.
call :list_devices
goto :eof

:list_devices
echo ========================================
echo   Active Virtual Devices
echo ========================================
echo.

REM Count devices
set "device_count=0"
for /f "tokens=*" %%a in ('wsl docker ps --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    set /a device_count+=1
)

if %device_count% equ 0 (
    echo [INFO] No active devices found
    goto :eof
)

echo Device ID       IP Address      Status      Uptime
echo --------------------------------------------------------
for /f "tokens=*" %%a in ('wsl docker ps --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    set "container_name=%%a"
    
    for /f "tokens=*" %%b in ('wsl docker exec !container_name! printenv DEVICE_ID 2^>nul') do set "device_id=%%b"
    for /f "tokens=*" %%c in ('wsl docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" !container_name! 2^>nul') do set "ip_addr=%%c"
    for /f "tokens=*" %%d in ('wsl docker inspect -f "{{.State.Status}}" !container_name! 2^>nul') do set "status=%%d"
    for /f "tokens=*" %%e in ('wsl docker ps --filter "name=!container_name!" --format "{{.RunningFor}}" 2^>nul') do set "uptime=%%e"
    
    echo !device_id!     !ip_addr!    !status!    !uptime!
)

echo.
echo [SUCCESS] Total devices: %device_count%
goto :eof

:start_devices
echo ========================================
echo   Starting Virtual Devices
echo ========================================

set "device_count=0"
for /f "tokens=*" %%a in ('wsl docker ps -a --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    set /a device_count+=1
)

if %device_count% equ 0 (
    echo [INFO] No devices found
    goto :eof
)

echo [INFO] Starting devices...
for /f "tokens=*" %%a in ('wsl docker ps -a --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    wsl docker start %%a >nul 2>&1
    echo [INFO] Started: %%a
)

echo [SUCCESS] Devices started
goto :eof

:stop_devices
echo ========================================
echo   Stopping Virtual Devices
echo ========================================

set "device_count=0"
for /f "tokens=*" %%a in ('wsl docker ps --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    set /a device_count+=1
)

if %device_count% equ 0 (
    echo [INFO] No active devices to stop
    goto :eof
)

echo [INFO] Stopping devices...
for /f "tokens=*" %%a in ('wsl docker ps --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    wsl docker stop %%a >nul 2>&1
    echo [INFO] Stopped: %%a
)

echo [SUCCESS] All devices stopped
goto :eof

:remove_devices
echo ========================================
echo   Removing Virtual Devices
echo ========================================

set /p "confirm=Are you sure you want to remove all virtual devices? (y/N): "
if /i not "%confirm%"=="y" (
    echo [INFO] Operation cancelled
    goto :eof
)

echo [INFO] Removing all virtual devices...

REM Stop and remove
for /f "tokens=*" %%a in ('wsl docker ps -a --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    wsl docker stop %%a >nul 2>&1
    wsl docker rm %%a >nul 2>&1
    echo [INFO] Removed: %%a
)

echo [SUCCESS] All devices removed
goto :eof

:view_logs
set "device_num=%2"

if "%device_num%"=="" (
    echo [ERROR] Please specify device number (e.g., 001, 002)
    exit /b 1
)

set "container_name=%DEVICE_CONTAINER_PREFIX%_%device_num%"

wsl docker ps --format "{{.Names}}" | findstr /x "%container_name%" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Device %device_num% not found or not running
    exit /b 1
)

echo [INFO] Showing logs for device %device_num% (Press Ctrl+C to exit)
echo.
wsl docker logs -f "%container_name%"
goto :eof

:show_stats
echo ========================================
echo   Device Statistics
echo ========================================
echo.

set "device_count=0"
for /f "tokens=*" %%a in ('wsl docker ps --filter "name=%DEVICE_CONTAINER_PREFIX%_" --format "{{.Names}}" 2^>nul') do (
    set /a device_count+=1
)

if %device_count% equ 0 (
    echo [INFO] No active devices found
    goto :eof
)

wsl docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" %DEVICE_CONTAINER_PREFIX%_*
goto :eof

:show_usage
echo ========================================
echo   Virtual Device Manager
echo ========================================
echo.
echo Usage: %~nx0 ^<command^> [options]
echo.
echo Commands:
echo   build                      Build device Docker image
echo   create ^<count^> [type]      Create N virtual devices
echo   list                       List all devices
echo   start                      Start stopped devices
echo   stop                       Stop all devices
echo   remove                     Remove all devices
echo   logs ^<device_num^>          View device logs (e.g., logs 001)
echo   stats                      Show device statistics
echo   help                       Show this help message
echo.
echo Device Types:
echo   iot_sensor    - IoT sensor (temp, humidity, pressure)
echo   smartphone    - Mobile device (location, battery)
echo   laptop        - Computer (CPU, memory, disk)
echo   camera        - Security camera (motion, recording)
echo   generic       - Generic device (default)
echo.
echo Examples:
echo   %~nx0 create 5                # Create 5 generic devices
echo   %~nx0 create 3 iot_sensor     # Create 3 IoT sensors
echo   %~nx0 list                    # List all devices
echo   %~nx0 logs 001                # View logs for device 001
echo   %~nx0 remove                  # Remove all devices
echo.
goto :eof
