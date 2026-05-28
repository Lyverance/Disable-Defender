@echo off
cd /d "%~dp0"
title Defender Status Check

set "SCRIPTDIR=%~dp0"

:: Auto-elevate: if not admin, relaunch with UAC
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c pushd ""%~dp0"" && ""%~f0""' -Verb RunAs -Wait"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\Check-Status.ps1"
