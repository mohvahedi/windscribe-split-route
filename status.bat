@echo off
cd /d "%~dp0"
title Windscribe Iran Bypass - Status
if exist "%USERPROFILE%\bin\iran-route.exe" (
    "%USERPROFILE%\bin\iran-route.exe" status
) else if exist "rust\target\release\iran-route.exe" (
    "rust\target\release\iran-route.exe" status
) else (
    echo [ERROR] iran-route.exe not found. Please run install.bat first.
)
echo.
pause
