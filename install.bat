@echo off
:: Batch Got Admin Check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Windscribe Iran Bypass - Native Rust Engine Installer
echo ===================================================
echo   Windscribe Iran Bypass - One-Click Installer
echo ===================================================
echo.

if not exist "%USERPROFILE%\bin" mkdir "%USERPROFILE%\bin"

:: Check for pre-built release binary or compile
if exist "rust\target\release\iran-route.exe" (
    echo [*] Installing pre-compiled binary...
    copy /y "rust\target\release\iran-route.exe" "%USERPROFILE%\bin\iran-route.exe" >nul
) else if exist "%~dp0iran-route.exe" (
    copy /y "%~dp0iran-route.exe" "%USERPROFILE%\bin\iran-route.exe" >nul
) else (
    echo [*] Compiling release binary with Cargo...
    cd rust && cargo build --release && cd ..
    copy /y "rust\target\release\iran-route.exe" "%USERPROFILE%\bin\iran-route.exe" >nul
)

:: Create CLI batch wrapper in %USERPROFILE%\bin
echo @echo off > "%USERPROFILE%\bin\iran-route.bat"
echo "%USERPROFILE%\bin\iran-route.exe" %%* >> "%USERPROFILE%\bin\iran-route.bat"

:: Apply routes and DNS split-tunnel
"%USERPROFILE%\bin\iran-route.exe" enable --force

:: Register native Windows Scheduled Task triggered on Network Connected (Event ID 10000) & Logon
echo [*] Registering native Windows Event Task (\IranRouteSync)...
schtasks /create /tn "\IranRouteSync" /tr "\"%USERPROFILE%\bin\iran-route.exe\" enable --silent" /sc onlogon /rl highest /f >nul 2>&1

echo.
echo ===================================================
echo   Installation complete!
echo ===================================================
echo.
pause
