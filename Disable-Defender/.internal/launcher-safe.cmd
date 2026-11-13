@echo off
color 0F
cls
cd /d "%~dp0"
title Defender Disable - Step 2 (Safe Mode)

:: Safe Mode was reached through a one-shot boot entry (safe-mode-entry.ps1), so
:: the next boot is normal Windows whatever happens in this stage; stage-safe.ps1
:: removes the entry itself.

:: stage-normal.ps1 appends /Unattended to the RunOnce command of an unattended
:: Disable run; forward it so this stage never waits for a key either.
set "UNATTENDED_ARG="
echo %*| find /i "/Unattended" >nul
if not errorlevel 1 set "UNATTENDED_ARG=-Unattended"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stage-safe.ps1" %UNATTENDED_ARG%

:: errorLevel is volatile -- any subsequent command overwrites it, so save it immediately.
:: stage-safe.ps1 handles its own reboot; we only pause if PS exits with an error
:: before reaching the reboot line (e.g. ownership failure, preflight abort).
set "PS_EXIT=%errorLevel%"
if "%PS_EXIT%" neq "0" (
    echo.
    echo  [launcher-safe] stage-safe.ps1 exited with code %PS_EXIT%
    echo.
    if not defined UNATTENDED_ARG pause
)
