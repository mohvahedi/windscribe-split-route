@echo off
cd /d "%~dp0"
title Windscribe Split-Route - Status
if exist "%USERPROFILE%\bin\split-route.exe" (
    "%USERPROFILE%\bin\split-route.exe" status
) else if exist "rust\target\release\split-route.exe" (
    "rust\target\release\split-route.exe" status
) else (
    echo [ERROR] split-route.exe not found. Please run install.bat first.
)
echo.
pause
