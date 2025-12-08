@echo off
echo ====================================
echo Network Security Dashboard
echo ====================================
echo.

cd /d "%~dp0"

echo Installing dependencies...
python -m pip install flask flask-cors psutil fastmcp -q

echo.
echo Starting dashboard (with auto-start MCP server)...
echo Dashboard will be available at: http://localhost:5100
echo Note: Network monitor API is on port 5000
echo.

python app.py

pause
