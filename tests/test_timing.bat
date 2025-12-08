@echo off
echo ========================================
echo Testing Agent with Timing Output
echo ========================================
echo.

cd /d E:\Malware_detection_using_Aiagent\Network_Security_poc\mcp_agent\client

echo Running query: "analyze for malware and threats"
echo.
echo You will see:
echo   - 🔄 Iteration X [STARTED]
echo   - 🤖 LLM Response [COMPLETED in Xs]
echo   - 🔧 tool_name [STARTED]
echo   - ✅ tool_name [COMPLETED in Xs]
echo   - ⏱️ TOTAL QUERY TIME: Xs
echo.
echo ========================================
echo.

E:\.venv\Scripts\python.exe agent.py "analyze for malware and threats"

echo.
echo ========================================
echo Test Complete!
echo ========================================
pause
