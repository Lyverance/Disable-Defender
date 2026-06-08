@echo off
cd /d "%~dp0"
title Defender Restore - Rollback
set "SCRIPTDIR=%~dp0"

:: Refuse to run in Safe Mode
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" >nul 2>&1
if %errorLevel% equ 0 (
    echo.
    echo  [ERROR] This script cannot run in Safe Mode.
    echo.
    echo  Reboot to normal mode first, then run Restore-Defender.cmd.
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

:: No pause here -- restore-from-backup.ps1 shows "save your files" only when
:: it is actually about to make changes.
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\restore-from-backup.ps1"

:: errorLevel is volatile -- any subsequent command overwrites it, so save it immediately.
:: If PS exits cleanly the window closes by itself; we only pause on error.
set "PS_EXIT=%errorLevel%"
if "%PS_EXIT%" neq "0" (
    echo.
    echo  [Script exited with error code %PS_EXIT%]
    pause
)
