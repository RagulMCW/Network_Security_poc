@echo off
echo ============================================================
echo Starting MCP Agent - Network Security Monitor
echo ============================================================
echo.
echo Activating virtual environment...
call E:\nos\.venv\Scripts\activate.bat
echo.
echo Starting agent...
echo.
python E:\nos\Network_Security_poc\mcp_agent\client\agent.py
