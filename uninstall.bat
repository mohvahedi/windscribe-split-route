@echo off
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
title Windscribe Iran Bypass - Uninstaller
echo ===================================================
echo   Windscribe Iran Bypass - Uninstaller
echo ===================================================
echo.
python iran_route.py uninstall
echo.
pause
