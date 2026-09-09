@echo off
:: Batch Got Admin Check
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\"\"' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0"
title Windscribe Iran Bypass - Installer
echo ===================================================
echo   Windscribe Iran Bypass - One-Click Installer
echo ===================================================
echo.
python iran_route.py install
echo.
pause
