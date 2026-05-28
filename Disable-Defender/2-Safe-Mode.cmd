@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title Defender Disable - Step 2 (Safe Mode)

:: Store script directory in a variable to safely handle spaces and brackets in path
set "SCRIPTDIR=%~dp0"

:: In Safe Mode UAC is not available — must be launched manually as Admin.
:: whoami /groups checks SID S-1-5-32-544 (Administrators) — works without LanmanServer.
whoami /groups | find "S-1-5-32-544" >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo  [ERROR] This script must be run as Administrator.
    echo.
    echo  How to do it in Safe Mode:
    echo    Right-click 2-Safe-Mode.cmd
    echo    Choose "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo.
echo  Defender Disable - Step 2 of 2 (Safe Mode)
echo  ============================================
echo.

:: ── [1/4] Take ownership of wscsvc and Sense ───────────────────────
echo [1/4] Taking ownership of wscsvc and Sense (registry)...

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\registry-privileges.ps1" -Action take

if %errorLevel% neq 0 (
    echo.
    echo  [ERROR] Failed to take ownership of registry keys.
    echo  Make sure you are in Safe Mode and running as Administrator.
    echo.
    pause
    exit /b 1
)

:: ── [2/4] Remove EPP context menu (must run after reboot — Windows restores these keys on boot) ──
echo [2/4] Removing EPP from context menu...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$keys = @(" ^
    "  'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'" ^
    ");" ^
    "foreach ($k in $keys) {" ^
    "  try {" ^
    "    $p = $k.Substring(0, $k.LastIndexOf('\'));" ^
    "    $c = $k.Substring($k.LastIndexOf('\') + 1);" ^
    "    $pk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($p, $true);" ^
    "    if ($pk) { $pk.DeleteSubKeyTree($c, $false); $pk.Close() }" ^
    "  } catch {} " ^
    "}"

echo     OK

:: ── [3/4] Disable services ──────────────────────────────────────────
echo [3/4] Disabling Defender services...

reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend"           /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter"            /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot"              /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc"            /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv"            /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense"               /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc"     /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /v Start /t REG_DWORD /d 4 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray        /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HealthCenter"                     /v DisableHealthCenter /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc"              /v Start /t REG_DWORD /d 4 /f >nul

echo     OK

:: ── [4/4] Return ownership to SYSTEM ───────────────────────────────
echo [4/4] Returning ownership to SYSTEM...

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\registry-privileges.ps1" -Action restore

echo     Done

:: ── [5/5] Exit Safe Mode ────────────────────────────────────────────
echo.
echo  All done. Rebooting to normal mode...
echo  After reboot: enable Tamper Protection back (step 2.4 in the guide).
echo.
echo  Press any key to reboot...
pause >nul

bcdedit /deletevalue {current} safeboot >nul
shutdown /r /t 0
