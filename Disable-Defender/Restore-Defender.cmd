@echo off
setlocal EnableDelayedExpansion
title Defender Enable - Rollback
cd /d "%~dp0"
set "SCRIPTDIR=%~dp0"

:: Auto-elevate: if not admin, relaunch with UAC
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c pushd ""%~dp0"" && ""%~f0""' -Verb RunAs -Wait"
    exit /b
)

echo.
echo  Defender Enable - Full Rollback
echo  =================================
echo.
echo  Save all open files before continuing.
echo  Press any key to start or close this window to cancel...
pause >nul

:: ── [1/4] Take ownership of Defender service keys ─────────────────
echo [1/4] Taking ownership of Defender service keys (registry)...

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\registry-privileges.ps1" -Action take

:: PPL-protected keys (WinDefend, WdFilter etc.) may show WARN — that is expected.
:: Fatal error only if non-PPL keys failed (exit code 1).
if %errorLevel% neq 0 (
    echo.
    echo  [ERROR] Failed to take ownership of non-PPL registry keys.
    echo  Make sure you are running as Administrator.
    echo.
    pause
    exit /b 1
)

:: ── [2/4] Restore services ─────────────────────────────────────────
echo [2/4] Restoring Defender services...

:: PPL-protected keys: use PowerShell SetValue directly for better token handling
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$keys = @{" ^
    "  'SYSTEM\CurrentControlSet\Services\WinDefend'           = 2;" ^
    "  'SYSTEM\CurrentControlSet\Services\WdFilter'            = 2;" ^
    "  'SYSTEM\CurrentControlSet\Services\WdBoot'              = 0;" ^
    "  'SYSTEM\CurrentControlSet\Services\WdNisSvc'            = 3;" ^
    "  'SYSTEM\CurrentControlSet\Services\WdNisDrv'            = 2;" ^
    "};" ^
    "foreach ($k in $keys.GetEnumerator()) {" ^
    "  try {" ^
    "    $reg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k.Key, $true);" ^
    "    if ($reg) { $reg.SetValue('Start', $k.Value, 'DWord'); $reg.Close();" ^
    "      Write-Host ('    OK: ' + $k.Key) -ForegroundColor Green }" ^
    "    else { Write-Host ('    SKIP (key not found): ' + $k.Key) -ForegroundColor Yellow }" ^
    "  } catch { Write-Host ('    WARN: ' + $k.Key + ' - ' + $_.Exception.Message) -ForegroundColor Yellow }" ^
    "}"

:: Non-PPL services — plain reg add is fine
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense"               /v Start /t REG_DWORD /d 3 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc"     /v Start /t REG_DWORD /d 3 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /v Start /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc"              /v Start /t REG_DWORD /d 2 /f >nul

echo     OK

:: ── [3/4] Restore scheduled tasks, notifications, tray, EPP ────────
echo [3/4] Restoring scheduled tasks, notifications and tray...

:: Scheduled tasks — schtasks не зависает в отличие от Enable-ScheduledTask
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Enable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup"           /Enable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"    /Enable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification"      /Enable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\AccountHealth\RecoverabilityToastTask"               /Enable >nul 2>&1

:: Notifications / SmartScreen / SecurityHealth
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray        /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\HealthCenter"                     /v DisableHealthCenter /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusDisableNotify /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusOverride      /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"         /v EnableSmartScreen  /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /f >nul 2>&1

:: EPP context menu — используем .NET Registry напрямую (без HKLM:\-провайдера, не зависает на *)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$guid = '{09A47860-11B0-4DA5-AFA5-26D86198A780}';" ^
    "$subkeys = @(" ^
    "  'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'," ^
    "  'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'" ^
    ");" ^
    "foreach ($s in $subkeys) {" ^
    "  try {" ^
    "    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($s, $true);" ^
    "    $k.SetValue('', $guid);" ^
    "    $k.Close();" ^
    "    Write-Host ('    OK: ' + $s) -ForegroundColor Green" ^
    "  } catch { Write-Host ('    WARN: ' + $s + ' - ' + $_.Exception.Message) -ForegroundColor Yellow }" ^
    "}"

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealth /t REG_EXPAND_SZ /d "%windir%\System32\SecurityHealthSystray.exe" /f >nul

echo     OK

:: ── [4/4] Return ownership to SYSTEM ──────────────────────────────
echo [4/4] Returning ownership to SYSTEM...

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTDIR%.internal\registry-privileges.ps1" -Action restore

echo     Done

:: ── Reboot ──────────────────────────────────────────────────────────
echo.
echo  Rollback complete.
echo  Press any key to reboot...
pause >nul

shutdown /r /t 0
