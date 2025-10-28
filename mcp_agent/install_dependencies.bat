@echo off
REM Install MCP Agent Dependencies

echo ========================================
echo Installing MCP Agent Dependencies
echo ========================================
echo.

REM Activate virtual environment
echo Activating virtual environment...
call E:\nos\.venv\Scripts\activate.bat

REM Install dependencies
echo.
echo Installing packages from requirements.txt...
pip install -r config\requirements.txt

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Copy config\env.example to config\.env
echo 2. Add your ANTHROPIC_API_KEY to config\.env
echo 3. Run: python query_agent.py "analyze network"
echo.
pause
