@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Windscribe Split-Route - Uninstaller
echo ===================================================
echo   Windscribe Split-Route - Rollback & Removal
echo ===================================================
echo.

if exist "%USERPROFILE%\bin\split-route.exe" (
    "%USERPROFILE%\bin\split-route.exe" disable
) else if exist "rust\target\release\split-route.exe" (
    "rust\target\release\split-route.exe" disable
)

echo [*] Removing Windows Scheduled Task (\SplitRouteSync)...
schtasks /delete /tn "\SplitRouteSync" /f >nul 2>&1

if exist "%USERPROFILE%\bin\split-route.exe" del /f /q "%USERPROFILE%\bin\split-route.exe" >nul 2>&1
if exist "%USERPROFILE%\bin\split-route.bat" del /f /q "%USERPROFILE%\bin\split-route.bat" >nul 2>&1
if exist "%USERPROFILE%\bin\split-route.log" del /f /q "%USERPROFILE%\bin\split-route.log" >nul 2>&1

echo.
echo ===================================================
echo   Uninstallation complete! All routes & tasks removed.
echo ===================================================
echo.
pause
