@echo off
REM View LLM AI Responses Log
echo.
echo ========================================
echo   LLM AI RESPONSES LOG
echo ========================================
echo.

cd /d "%~dp0"

REM Extract LLM logs first
echo Extracting LLM responses from beelzebub.log...
python extract_llm_logs.py

echo.
echo ========================================
echo.

if not exist "logs\llm_responses.jsonl" (
    echo No LLM responses found yet.
    pause
    exit /b
)

echo Opening LLM responses log...
echo.
notepad logs\llm_responses.jsonl
