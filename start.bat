@echo off
title Phishing URL Scanner
cd /d "%~dp0"

REM Add common Node.js install locations to PATH for this window
set "NODE1=C:\Program Files\nodejs"
set "NODE2=C:\Program Files (x86)\nodejs"
set "NODE3=%APPDATA%\npm"
set "PATH=%NODE1%;%NODE2%;%NODE3%;%PATH%"

where node >nul 2>&1
if errorlevel 1 (
    echo.
    echo Node.js was not found. Please install it from https://nodejs.org
    echo Then run this script again.
    echo.
    pause
    exit /b 1
)

echo Installing dependencies if needed...
call npm install
if errorlevel 1 (
    echo npm install failed.
    pause
    exit /b 1
)

echo.
echo Starting Phishing URL Scanner...
echo Open your browser to:  http://localhost:3000
echo Press Ctrl+C to stop the server.
echo.
node server.js
pause
