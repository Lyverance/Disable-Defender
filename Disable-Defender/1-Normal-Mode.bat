@echo off
cd /d "%~dp0"
title Defender Disable - Step 1

:: Auto-elevate: if not admin, relaunch with UAC
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c pushd ""%~dp0"" && ""%~f0""' -Verb RunAs -Wait"
    exit /b
)

:: Store script directory in a variable to safely handle spaces and brackets in path
set "SCRIPTDIR=%~dp0"

echo.
echo  Defender Disable - Step 1 of 2
echo  ================================
echo  This script will disable Defender tasks and reboot into Safe Mode.
echo  After reboot: run 2-Safe-Mode.cmd as Administrator.
echo.
echo  Save all open files before continuing.
echo  Press any key to start or close this window to cancel...
pause >nul

:: Set ExecutionPolicy so Check-Status.ps1 works via context menu after all steps are done
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\disable-stage1.ps1"
