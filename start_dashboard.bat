@echo off
title Disk Cleanup Dashboard
cd /d "%~dp0"

rem If the server is already listening on 8765, just open the browser.
netstat -ano | findstr /R /C:":8765 .*LISTENING" >nul
if %errorlevel%==0 (
    echo Server already running. Opening dashboard...
    start "" http://localhost:8765
    exit /b
)

echo Starting Disk Cleanup Dashboard on http://localhost:8765
echo Close this window to stop the server.
python server.py
pause
