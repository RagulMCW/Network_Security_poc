@echo off
REM View SSH Attacker Logs

echo ========================================
echo SSH Attacker Logs
echo ========================================
echo.
echo Choose an option:
echo.
echo 1. View Docker Container Logs (Live)
echo 2. View Detailed Attack Log
echo 3. View Summary Log
echo 4. View Latest Summary (Tail)
echo.
set /p choice="Enter choice (1-4): "

if "%choice%"=="1" (
    echo.
    echo Starting live container logs... (Press Ctrl+C to exit)
    wsl docker logs -f ssh-attacker
) else if "%choice%"=="2" (
    echo.
    cd /d "%~dp0"
    if exist logs\ssh_attacks_*.log (
        for /f %%i in ('dir /b /o-d logs\ssh_attacks_*.log') do (
            echo Showing: %%i
            type logs\%%i
            goto :done
        )
    ) else (
        echo No attack logs found yet.
    )
) else if "%choice%"=="3" (
    echo.
    cd /d "%~dp0"
    if exist logs\ssh_summary.log (
        type logs\ssh_summary.log
    ) else (
        echo No summary log found yet.
    )
) else if "%choice%"=="4" (
    echo.
    echo Showing latest summary entries...
    wsl bash -c "tail -f /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker/logs/ssh_summary.log"
) else (
    echo Invalid choice.
)

:done
echo.
pause
