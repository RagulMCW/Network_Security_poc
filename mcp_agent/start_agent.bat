@echo off
REM Network Security Monitor - MCP Agent Launcher
REM Activates virtual environment and starts the agent

echo.
echo ============================================================
echo Network Security Monitor - Starting Agent
echo ============================================================
echo.

REM Activate virtual environment
call E:\nos\.venv\Scripts\activate.bat

REM Check if activation succeeded
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment at E:\nos\.venv
    echo Please ensure the virtual environment exists.
    pause
    exit /b 1
)

echo Virtual environment activated!
echo.

REM Navigate to MCP agent directory
cd /d E:\nos\Network_Security_poc\mcp_agent

REM Run the agent
python run_agent.py

REM Deactivate when done
call deactivate
