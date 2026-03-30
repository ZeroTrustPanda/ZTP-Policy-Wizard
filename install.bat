@echo off
title ZTP Policy Wizard - Installation
echo.
echo ============================================================
echo   ZTP Policy Wizard - Zscaler Template Policy Configuration
echo   Windows Server Installation
echo ============================================================
echo.

:: Check for Node.js
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo.
    echo Please install Node.js 18+ from: https://nodejs.org/
    echo After installation, re-run this script.
    echo.
    pause
    exit /b 1
)

:: Check Node.js version
for /f "tokens=1 delims=v" %%a in ('node -v') do set NODE_VER=%%a
echo [OK] Node.js found: %NODE_VER%

:: Install dependencies
echo.
echo Installing dependencies...
cd /d "%~dp0"
call npm install
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

:: Create logs directory
if not exist "logs" mkdir logs
echo [OK] Logs directory ready.

echo.
echo ============================================================
echo   Installation complete!
echo.
echo   To start the server:
echo     npm start
echo.
echo   Or run directly:
echo     node server\index.js
echo.
echo   Default URL: http://localhost:3000
echo.
echo   Environment variables (optional):
echo     ZTP_PORT=3000    (change listening port)
echo     ZTP_HOST=0.0.0.0 (change listening address)
echo.
echo   To run as a Windows Service, use:
echo     npm install -g node-windows
echo     (then use the service-install.js script)
echo ============================================================
echo.
pause
