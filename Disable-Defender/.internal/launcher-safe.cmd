@echo off
color 0F
cls
cd /d "%~dp0"
title Defender Disable - Step 2 (Safe Mode)

:: ── Clear Safe Mode flag immediately ──────────────────────────────────────
:: Done HERE, before stage-safe runs, so a crash or power loss mid-script
:: does not leave Windows stuck booting into Safe Mode forever.
:: If the flag is already gone (repeat run), bcdedit exits non-zero -- ignore it.
bcdedit /deletevalue "{current}" safeboot >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stage-safe.ps1"

:: errorLevel is volatile -- any subsequent command overwrites it, so save it immediately.
:: stage-safe.ps1 handles its own reboot; we only pause if PS exits with an error
:: before reaching the reboot line (e.g. ownership failure, preflight abort).
set "PS_EXIT=%errorLevel%"
if "%PS_EXIT%" neq "0" (
    echo.
    echo  [launcher-safe] stage-safe.ps1 exited with code %PS_EXIT%
    echo.
    pause
)
