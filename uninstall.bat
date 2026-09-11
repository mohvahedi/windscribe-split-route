@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Windscribe Iran Bypass - Uninstaller
echo ===================================================
echo   Windscribe Iran Bypass - Rollback & Removal
echo ===================================================
echo.

if exist "%USERPROFILE%\bin\iran-route.exe" (
    "%USERPROFILE%\bin\iran-route.exe" disable
) else if exist "rust\target\release\iran-route.exe" (
    "rust\target\release\iran-route.exe" disable
)

echo [*] Removing Windows Scheduled Task (\IranRouteSync)...
schtasks /delete /tn "\IranRouteSync" /f >nul 2>&1

if exist "%USERPROFILE%\bin\iran-route.exe" del /f /q "%USERPROFILE%\bin\iran-route.exe" >nul 2>&1
if exist "%USERPROFILE%\bin\iran-route.bat" del /f /q "%USERPROFILE%\bin\iran-route.bat" >nul 2>&1
if exist "%USERPROFILE%\bin\iran-route.log" del /f /q "%USERPROFILE%\bin\iran-route.log" >nul 2>&1

echo.
echo ===================================================
echo   Uninstallation complete! All routes & tasks removed.
echo ===================================================
echo.
pause
