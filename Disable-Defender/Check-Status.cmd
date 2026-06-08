@echo off
cd /d "%~dp0"
title Defender Status Check

set "SCRIPTDIR=%~dp0"

:: Refuse to run in Safe Mode
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" >nul 2>&1
if %errorLevel% equ 0 (
    echo.
    echo  [ERROR] This script cannot run in Safe Mode.
    echo.
    echo  Reboot to normal mode first, then run Check-Status.cmd.
    echo.
    pause
    exit /b 1
)

:: Auto-elevate: if not admin, relaunch with UAC
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c pushd ""%~dp0"" && ""%~f0""' -Verb RunAs -Wait"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\Check-Status.ps1"

:: errorLevel is volatile -- any subsequent command overwrites it, so save it immediately.
:: Fallback pause catches the case where PS exits with an error before its own pause.
set "PS_EXIT=%errorLevel%"
if "%PS_EXIT%" neq "0" (
    echo.
    echo  [Script exited with error code %PS_EXIT%]
    pause
)
