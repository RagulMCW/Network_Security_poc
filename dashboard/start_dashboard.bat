@echo off
echo ====================================
echo Network Security Dashboard
echo ====================================
echo.

cd /d "%~dp0"

echo Installing dependencies...
python -m pip install flask flask-cors

echo.
echo Starting dashboard...
echo Dashboard will be available at: http://localhost:5100
echo Note: Network monitor API is on port 5000
echo.

python app.py

pause
