@echo off
setlocal
set RUNTIME=%~dp0
if "%XRAY_MANAGER_HOME%"=="" set XRAY_MANAGER_HOME=%RUNTIME%
if "%PORT%"=="" set PORT=54321
where node >nul 2>nul
if errorlevel 1 (
  echo [xray-manager-v4] Node.js is required but was not found in PATH.
  echo Install Node.js 20+ from https://nodejs.org/ and run this file again.
  pause
  exit /b 1
)
echo [xray-manager-v4] Starting http://127.0.0.1:%PORT%
node "%RUNTIME%index.js"
pause
