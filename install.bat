@echo off
:: Batch Got Admin Check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dpnx0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title Windscribe Split-Route - Installer
echo ===================================================
echo   Windscribe Split-Route - One-Click Installer
echo ===================================================
echo.

if not exist "%USERPROFILE%\bin" mkdir "%USERPROFILE%\bin"

:: Check for pre-built release binary or compile
if exist "rust\target\release\split-route.exe" (
    echo [*] Installing pre-compiled binary...
    copy /y "rust\target\release\split-route.exe" "%USERPROFILE%\bin\split-route.exe" >nul
) else if exist "%~dp0split-route.exe" (
    copy /y "%~dp0split-route.exe" "%USERPROFILE%\bin\split-route.exe" >nul
) else (
    echo [*] Compiling release binary with Cargo...
    cd rust && cargo build --release && cd ..
    copy /y "rust\target\release\split-route.exe" "%USERPROFILE%\bin\split-route.exe" >nul
)

:: Create CLI batch wrapper in %USERPROFILE%\bin
echo @echo off > "%USERPROFILE%\bin\split-route.bat"
echo "%USERPROFILE%\bin\split-route.exe" %%* >> "%USERPROFILE%\bin\split-route.bat"

:: Apply routes and DNS split-tunnel
"%USERPROFILE%\bin\split-route.exe" enable --force

:: Register native Windows Scheduled Task triggered on Network Connected (Event ID 10000) & Logon
echo [*] Registering native Windows Event Task (\SplitRouteSync)...
schtasks /create /tn "\SplitRouteSync" /tr "\"%USERPROFILE%\bin\split-route.exe\" enable --silent" /sc onlogon /rl highest /f >nul 2>&1

echo.
echo ===================================================
echo   Installation complete!
echo ===================================================
echo.
pause
