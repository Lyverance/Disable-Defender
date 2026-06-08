<#
  restore-from-backup.ps1
  Restores Defender settings from defender-backup.json created by stage-normal.ps1.
  If backup is missing or a value was null, uses safe defaults.
  Run via Restore-Defender.cmd (UAC elevation is automatic).
#>

$ErrorActionPreference = 'Stop'

# ── Helpers ────────────────────────────────────────────────────────

function Sep { Write-Host ("  " + ("=" * 38)) -ForegroundColor DarkGray }

function Restore-Val($backupVal, $defaultVal) {
    if ($null -ne $backupVal) { return $backupVal }
    return $defaultVal
}

# Invoke-ReadKey: wraps RawUI.ReadKey with a fallback for non-interactive hosts
# (RMM agents, WinRM, Task Scheduler). RawUI.ReadKey throws HostException in those
# environments; with $ErrorActionPreference='Stop' that is an unhandled crash.
function Invoke-ReadKey {
    try {
        $keyInfo = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        return $keyInfo.Character
    } catch {
        $response = Read-Host
        return if ($response.Length -gt 0) { $response[0] } else { '' }
    }
}

function Restore-Dword($path, $name, $val) {
    if ($null -eq $val -or $val -is [System.DBNull] -or $val -eq '') {
        # *> $null preserves $LASTEXITCODE; | Out-Null resets it to 0 in PS 5.1.
        reg delete "$path" /v "$name" /f *> $null
    } else {
        reg add "$path" /v "$name" /t REG_DWORD /d ([int]$val) /f *> $null
    }
}
function Restore-Sz($path, $name, $val) {
    if ($null -eq $val -or $val -is [System.DBNull] -or $val -eq '') {
        reg delete "$path" /v "$name" /f *> $null
    } else {
        # Quotes around $val are mandatory -- spaces in the value (e.g. %ProgramFiles%\...) break reg.exe without them.
        reg add "$path" /v "$name" /t REG_SZ /d "$val" /f *> $null
    }
}
function Get-RegValOrNull($path, $name) {
    try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null }
}

# ── Header ─────────────────────────────────────────────────────────
Sep
Write-Host "  Defender Restore  --  Full Rollback" -ForegroundColor Cyan
Sep
Write-Host ""

# ── Load & validate backup ────────────────────────────────────────
# A truncated or manually edited JSON produces an explicit [ERROR] rather
# than a silent $null fallback that would silently apply hardcoded defaults.
$backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
$backup     = $null

if (Test-Path $backupPath) {
    try {
        $rawJson = Get-Content $backupPath -Raw -Encoding UTF8
        $parsed  = $rawJson | ConvertFrom-Json
        if ($null -eq $parsed.Timestamp -or $null -eq $parsed.Services) {
            throw 'Required fields Timestamp / Services are missing'
        }
        $backup = $parsed
        $backupTimestamp = [datetime]::Parse($backup.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd HH:mm')
        Write-Host ("  Backup: " + $backupTimestamp) -ForegroundColor DarkGray
    } catch {
        Write-Host "  [ERROR] Backup file found but corrupted: $_" -ForegroundColor Red
        Write-Host "  Falling back to hardcoded defaults." -ForegroundColor Yellow
        $backup = $null
    }
}

Write-Host ""

# ── Preflight: warn if no backup and Defender is active ───────────
$alreadyConfirmed = $false

if (-not $backup) {
    $defenderRunning = (Get-Service -Name WinDefend -ErrorAction SilentlyContinue).Status -eq 'Running'
    if ($defenderRunning) {
        Write-Host "  [WARNING] No backup file (defender-backup.json) found." -ForegroundColor Yellow
        Write-Host "            Windows Defender appears to be already active." -ForegroundColor DarkGray
        Write-Host "            This system has not been modified by this tool." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Apply hardcoded defaults anyway? (Y/N): " -NoNewline -ForegroundColor Yellow
        $confirmChar = Invoke-ReadKey
        Write-Host $confirmChar
        Write-Host ""
        if ($confirmChar -ne 'y' -and $confirmChar -ne 'Y') {
            Write-Host "  Exiting." -ForegroundColor DarkGray
            Write-Host ""
            exit 0
        }
        $alreadyConfirmed = $true
    }
}

# Start values: 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
# WdBoot=0 is correct -- it is a boot-start driver controlled by Secure Boot / TPM, not a normal service
$serviceDefaults = @{ WinDefend=2; WdFilter=2; WdBoot=0; WdNisSvc=3; WdNisDrv=2; Sense=3; webthreatdefsvc=3; webthreatdefusersvc=2; wscsvc=2 }

# ── Already-restored check ────────────────────────────────────────
#
#  Compare current state against the backup before touching anything.
#  If everything already matches, skip the whole restore -- no need
#  to hammer registry ownership and risk a false FAIL.
#
if ($backup) {
    $alreadyRestored = $true

    foreach ($svcName in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv','Sense','webthreatdefsvc','webthreatdefusersvc','wscsvc')) {
        $expectedStart = if ($null -ne $backup.Services.$svcName) { [int]$backup.Services.$svcName } else { $serviceDefaults[$svcName] }
        $actualStart   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name Start -ErrorAction SilentlyContinue).Start
        if ($actualStart -ne $expectedStart) { $alreadyRestored = $false; break }
    }

    # Security Center: AntiVirusDisableNotify (was it 0/absent before disable?)
    if ($alreadyRestored) {
        $scBackup         = $backup.SecurityCenter
        $currentAVDN      = Get-RegValOrNull 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify'
        $expectedAVDN     = if ($scBackup -and $null -ne $scBackup.AntiVirusDisableNotify) { [int]$scBackup.AntiVirusDisableNotify } else { $null }
        if ($currentAVDN -ne $expectedAVDN) { $alreadyRestored = $false }
    }

    if ($alreadyRestored) {
        Write-Host "  [OK] System is already in its original state." -ForegroundColor Green
        Write-Host "       No restoration needed." -ForegroundColor DarkGray
        Write-Host ""
        Sep
        Write-Host "  ALL OK" -ForegroundColor Green
        Sep
        Write-Host ""
        Invoke-ReadKey *> $null
        exit 0
    }
}

# ── Confirm before making any changes ─────────────────────────────
if (-not $alreadyConfirmed) {
    Write-Host "  Save all open files.  Press any key to continue or close to cancel..." -ForegroundColor Yellow
    Invoke-ReadKey *> $null
    Write-Host ""
}

# ── [1/3] Take ownership ──────────────────────────────────────────
Write-Host "  [1/3] Taking registry ownership..." -NoNewline -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action take *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAIL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [ERROR] Failed to take ownership. Run as Administrator." -ForegroundColor Red
    Write-Host ""
    Invoke-ReadKey *> $null
    exit 1
}
Write-Host "  OK" -ForegroundColor Green

# ── [2/3] Restore all settings ────────────────────────────────────
Write-Host "  [2/3] Restoring Defender settings..." -NoNewline -ForegroundColor Yellow
try {
# Services
# Restore Start value in ALL concrete ControlSets (001, 002, etc.) plus the alias.
# stage-safe.ps1 wrote to all of them when disabling -- we must mirror that here,
# otherwise Windows may boot from ControlSet001/002 with Start=4 still set.
# Each probe handle is closed immediately after the existence check.
$restoreControlSets = [System.Collections.Generic.List[string]]@('CurrentControlSet')
foreach ($controlSetIndex in 1..3) {
    $csName          = 'ControlSet{0:D3}' -f $controlSetIndex
    $controlSetProbe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName")
    if ($null -ne $controlSetProbe) {
        $controlSetProbe.Close()
        $restoreControlSets.Add($csName)
    }
}

$servicesToRestore = @(
    'WinDefend','WdFilter','WdBoot','WdNisSvc','WdNisDrv',
    'Sense','webthreatdefsvc','webthreatdefusersvc','wscsvc'
)

foreach ($svcName in $servicesToRestore) {
    $backupStartValue = if ($backup) { $backup.Services.$svcName } else { $null }
    $targetStartValue = [int](Restore-Val $backupStartValue $serviceDefaults[$svcName])
    foreach ($csName in $restoreControlSets) {
        $registryKey = $null
        try {
            $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                "SYSTEM\$csName\Services\$svcName", $true)
            if ($null -eq $registryKey) { continue }  # key absent in this ControlSet -- not an error
            # [RegistryValueKind]::DWord enum is required -- passing the string 'DWord' silently writes REG_SZ.
            $registryKey.SetValue('Start', $targetStartValue, [Microsoft.Win32.RegistryValueKind]::DWord)
        } catch {
            Write-Host ""
            Write-Host "  [ERROR] Failed to restore '$svcName' in $csName`: $_" -ForegroundColor Red
        } finally {
            if ($null -ne $registryKey) { $registryKey.Close() }
        }
    }
}

# Scheduled tasks
$taskDefs = @(
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cache Maintenance'; Key='CacheMaintenance'    }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cleanup';           Key='Cleanup'             }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Scheduled Scan';    Key='ScheduledScan'       }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Verification';      Key='Verification'        }
    @{ Path='\Microsoft\Windows\AccountHealth\';    Name='RecoverabilityToastTask';            Key='RecoverabilityToast' }
)
foreach ($taskDef in $taskDefs) {
    $wasEnabled = if ($backup -and $null -ne $backup.ScheduledTasks.($taskDef.Key)) { [bool]$backup.ScheduledTasks.($taskDef.Key) } else { $true }
    if ($wasEnabled) {
        try {
            Enable-ScheduledTask -TaskPath $taskDef.Path -TaskName $taskDef.Name -ErrorAction SilentlyContinue *> $null
        } catch {
            Write-Host "  [WARNING] Could not enable scheduled task '$($taskDef.Name)': $_" -ForegroundColor Yellow
        }
    }
}

# Security Center / SmartScreen / tray
$scBackup = if ($backup) { $backup.SecurityCenter } else { $null }
$ssBackup = if ($backup) { $backup.SmartScreen    } else { $null }
$stBackup = if ($backup) { $backup.Systray        } else { $null }

$avDisableNotify = if ($scBackup) { $scBackup.AntiVirusDisableNotify } else { $null }
$avOverride      = if ($scBackup) { $scBackup.AntiVirusOverride      } else { $null }
$toastEnabled    = if ($scBackup) { $scBackup.ToastNotifyEnabled     } else { $null }
$ssPolicy        = if ($ssBackup) { $ssBackup.PolicyValue            } else { $null }
$ssExplorerVal   = if ($ssBackup) { $ssBackup.ExplorerValue          } else { $null }
$webContentEval  = if ($ssBackup) { $ssBackup.AppHostValue           } else { $null }
$hideSystray     = if ($stBackup) { $stBackup.HideSystray            } else { $null }
$disableHealth   = if ($stBackup) { $stBackup.DisableHealthCenter    } else { $null }

Restore-Dword 'HKLM\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify' $avDisableNotify
Restore-Dword 'HKLM\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride'      $avOverride
Restore-Dword 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled' $toastEnabled
Restore-Dword 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'         'EnableSmartScreen'  $ssPolicy
Restore-Sz    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' $ssExplorerVal
Restore-Dword 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost'  'EnableWebContentEvaluation' $webContentEval

# Remove ACL deny on smartscreen.exe set by stage-safe.ps1
# Test-Path guard: smartscreen.exe is absent on Windows Server Core.
$smartscreenExe = "$env:SystemRoot\System32\smartscreen.exe"
if (Test-Path $smartscreenExe) {
    takeown /f "$smartscreenExe" /a *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host "  [WARNING] takeown on smartscreen.exe failed (exit $LASTEXITCODE)" -ForegroundColor Yellow }
    icacls "$smartscreenExe" /remove:d "*S-1-5-32-545" *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host "  [WARNING] icacls on smartscreen.exe failed (exit $LASTEXITCODE)"  -ForegroundColor Yellow }
}

Restore-Dword 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray'        $hideSystray
Restore-Dword 'HKLM\SOFTWARE\Policies\Microsoft\Windows\HealthCenter'                     'DisableHealthCenter' $disableHealth

# EPP context menu
$eppMap = @{
    Star      = 'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'
    Drive     = 'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'
    Directory = 'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'
    DirBg     = 'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'
    Folder    = 'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
}
$defaultEppGuid = '{09A47860-11B0-4DA5-AFA5-26D86198A780}'

foreach ($eppEntry in $eppMap.GetEnumerator()) {
    $backupGuid = if ($backup -and $null -ne $backup.EppContextMenu.($eppEntry.Key)) { $backup.EppContextMenu.($eppEntry.Key) } else { $null }
    if ($null -eq $backupGuid) {
        # Key was absent before -- remove it
        $parentPath = $eppEntry.Value.Substring(0, $eppEntry.Value.LastIndexOf('\'))
        $childName  = $eppEntry.Value.Substring($eppEntry.Value.LastIndexOf('\') + 1)
        $parentKey  = $null
        try {
            $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentPath, $true)
            if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree($childName, $false) }
        } catch {
            Write-Host "  [WARNING] Could not remove EPP key '$($eppEntry.Key)': $_" -ForegroundColor Yellow
        } finally {
            if ($null -ne $parentKey) { $parentKey.Close() }
        }
    } else {
        # Key was present -- restore it with the backed-up (or default) GUID
        $eppGuid = if ($backupGuid -ne '') { $backupGuid } else { $defaultEppGuid }
        $eppKey  = $null
        try {
            $eppKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($eppEntry.Value, $true)
            $eppKey.SetValue('', $eppGuid)
        } catch {
            Write-Host "  [WARNING] Could not restore EPP key '$($eppEntry.Key)': $_" -ForegroundColor Yellow
        } finally {
            if ($null -ne $eppKey) { $eppKey.Close() }
        }
    }
}

# SecurityHealth autorun
$shEntry = if ($backup) { $backup.SecurityHealthAutorun } else { $null }
# Backward compatibility: old backup format stored a plain string, new format stores {Value, Type}
if ($shEntry -is [string]) {
    $shValue = $shEntry
    $shType  = $null
} else {
    $shValue = if ($shEntry) { $shEntry.Value } else { $null }
    $shType  = if ($shEntry -and $shEntry.Type) { $shEntry.Type } else { $null }
}
if ($null -eq $shValue) {
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityHealth' -ErrorAction SilentlyContinue
} else {
    # Use backed-up type if available; fall back to inferring from value
    $regType = if ($shType -eq 'ExpandString') { 'REG_EXPAND_SZ' }
               elseif ($shType -eq 'String')   { 'REG_SZ' }
               elseif ($shValue -like '*%*')    { 'REG_EXPAND_SZ' }
               else                             { 'REG_SZ' }
    reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v SecurityHealth /t $regType /d "$shValue" /f *> $null
}

Write-Host "  OK" -ForegroundColor Green
} catch {
    Write-Host "  FAIL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [ERROR] Failed to restore one or more settings:" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Defender may not be fully restored. Check the output above." -ForegroundColor Yellow
    Write-Host ""
    Invoke-ReadKey *> $null
    exit 1
}

# ── [3/3] Restore ownership ───────────────────────────────────────
Write-Host "  [3/3] Returning ownership to SYSTEM..." -NoNewline -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [WARNING] Failed to return registry ownership to SYSTEM." -ForegroundColor Yellow
    Write-Host "  Defender is restored, but registry keys are still owned by Administrators." -ForegroundColor DarkGray
    Write-Host "  Reboot and re-run Restore-Defender.cmd to retry." -ForegroundColor DarkGray
    Write-Host ""
} else {
    Write-Host "  OK" -ForegroundColor Green
}

# ── Done ──────────────────────────────────────────────────────────
Write-Host ""
Sep
Write-Host "  Done. Rebooting..." -ForegroundColor Green
Sep
Write-Host ""
Write-Host "  Press any key to reboot..." -ForegroundColor Yellow
Invoke-ReadKey *> $null

shutdown /r /t 0
if ($LASTEXITCODE -ne 0) {
    # shutdown.exe absent (Embedded / LTSB / Server Core) -- fallback to WMI cmdlet
    Restart-Computer -Force
}
