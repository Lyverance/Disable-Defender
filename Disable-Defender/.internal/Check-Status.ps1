# Check-Status.ps1 -- Defender state verification (works both ways: disabled-check and restore-check)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$script:PassCount = 0
$script:FailCount = 0

trap {
    Write-Host ""
    Write-Host "  [FATAL ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "  Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# ── Helpers ────────────────────────────────────────────────────────

function Sep { Write-Host ("  " + ("=" * 38)) -ForegroundColor DarkGray }

function Check($label, $ok) {
    if ($ok) {
        Write-Host ("  [OK]   " + $label) -ForegroundColor Green
        $script:PassCount++
    } else {
        Write-Host ("  [DIFF] " + $label) -ForegroundColor Red
        $script:FailCount++
    }
}

# CheckOK: item that is informational / always correct -- NOT counted in $PassCount.
# $PassCount is only incremented by Check() on a true verified success;
# informational items (skipped, n/a, already-correct) don't inflate the pass ratio.
function CheckOK($label) {
    Write-Host ("  [OK]   " + $label) -ForegroundColor DarkGray
    # Intentionally NOT incrementing $script:PassCount -- this is informational, not a verified check.
}

function RegAbsent($path, $name) {
    try { $null = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name; return $false }
    catch { return $true }
}

function RegValue($path, $name, $expected) {
    try { return ((Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name -eq $expected) }
    catch { return $false }
}

function KeyAbsent($subkeyPath) {
    # OpenSubKey returns $null for both absent key and access denied -- absence is a legitimate state.
    $registryKey = $null
    try {
        $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath)
        if ($null -eq $registryKey) { return $true }
        return $false
    } catch {
        return $true
    } finally {
        if ($null -ne $registryKey) { $registryKey.Close() }
    }
}

function ServiceDisabled($svcName) {
    # Read directly from registry -- Get-Service reads from SCM which may not
    # reflect registry changes made in Safe Mode until next full SCM init.
    # Start=4 means Disabled.
    $startValue = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name Start -ErrorAction SilentlyContinue).Start
    if ($null -eq $startValue) { return $true }   # key absent = treat as disabled
    return ($startValue -eq 4)
}

function TaskDisabled($taskPath, $taskName) {
    $taskObject = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $taskObject) { return $true }
    return ($taskObject.State -eq 'Disabled')
}

# Checks that the current DWORD registry value matches the backup.
# If backup was null, the key should be absent.
function CheckRestoredDword($label, $regPath, $regName, $backupVal) {
    if ($null -eq $backupVal -or $backupVal -is [System.DBNull]) {
        if (RegAbsent $regPath $regName) {
            CheckOK ($label + ' - absent')
        } else {
            Check ($label + ' - should be absent') $false
        }
    } else {
        Check ($label + ' = ' + $backupVal) (RegValue $regPath $regName ([int]$backupVal))
    }
}

function CheckRestoredSz($label, $regPath, $regName, $backupVal) {
    if ($null -eq $backupVal -or $backupVal -is [System.DBNull]) {
        if (RegAbsent $regPath $regName) {
            CheckOK ($label + " - absent")
        } else {
            Check ($label + ' - should be absent') $false
        }
    } else {
        Check ($label + " = '" + $backupVal + "'") (RegValue $regPath $regName $backupVal)
    }
}

# ── Load backup (for restore-mode comparison) ─────────────────────
$backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
$backup     = $null
if (Test-Path $backupPath) {
    try {
        $rawJson = Get-Content $backupPath -Raw -Encoding UTF8
        $backup  = $rawJson | ConvertFrom-Json
        if ($null -eq $backup.Timestamp -or $null -eq $backup.Services) {
            throw 'Required fields Timestamp / Services are missing'
        }
    } catch {
        Write-Host "  [WARNING] Backup file found but could not be parsed: $_" -ForegroundColor Yellow
        $backup = $null
    }
}

# ── Auto-detect mode ──────────────────────────────────────────────
$defenderOff = ServiceDisabled 'WinDefend'

if ($defenderOff) {
    $statusText  = 'DISABLED'
    $statusColor = 'Red'
} else {
    $statusText  = 'ENABLED'
    $statusColor = 'Green'
}

Write-Host ""
Sep
Write-Host ("  Status : " + $statusText) -ForegroundColor $statusColor
if ($backup) {
    $backupTimestamp = [datetime]::Parse($backup.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd HH:mm')
    Write-Host ("  Backup : " + $backupTimestamp) -ForegroundColor DarkGray
}
Sep
Write-Host ""

# No backup + Defender enabled = untouched system, nothing to check
if (-not $defenderOff -and -not $backup) {
    Write-Host "  Defender is enabled and no backup was found." -ForegroundColor DarkGray
    Write-Host "  Nothing has been changed on this system yet." -ForegroundColor DarkGray
    Write-Host ""
    pause
    exit 0
}

# ── Services ──────────────────────────────────────────────────────
Write-Host "  [Services]" -ForegroundColor Yellow

$svcDefaults = @{
    WinDefend=2; WdFilter=2; WdNisSvc=3; WdNisDrv=2
    Sense=3; webthreatdefsvc=3; webthreatdefusersvc=2
    wscsvc=2    # Windows Security Center
}

if ($defenderOff) {
    Check 'WinDefend           - Disabled'  (ServiceDisabled 'WinDefend')
    Check 'WdFilter            - Disabled'  (ServiceDisabled 'WdFilter')
    Check 'WdNisSvc            - Disabled'  (ServiceDisabled 'WdNisSvc')
    Check 'WdNisDrv            - Disabled'  (ServiceDisabled 'WdNisDrv')
    Check 'Sense               - Disabled'  (ServiceDisabled 'Sense')
    Check 'webthreatdefsvc     - Disabled'  (ServiceDisabled 'webthreatdefsvc')
    Check 'webthreatdefusersvc - Disabled'  (ServiceDisabled 'webthreatdefusersvc')
    Check 'wscsvc              - Disabled'  (ServiceDisabled 'wscsvc')
} else {
    foreach ($svcName in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv','Sense','webthreatdefsvc','webthreatdefusersvc','wscsvc')) {
        $expectedStart = if ($backup -and $null -ne $backup.Services.$svcName) { [int]$backup.Services.$svcName } else { $svcDefaults[$svcName] }
        $actualStart   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name Start -ErrorAction SilentlyContinue).Start
        Check "$svcName - Start = $expectedStart" ($actualStart -eq $expectedStart)
    }
}
$wdBootStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot' -Name Start -ErrorAction SilentlyContinue).Start
$wdBootStr   = if ($null -ne $wdBootStart) { "$wdBootStart" } else { 'n/a' }
Write-Host ("  [INFO] WdBoot               - Start = " + $wdBootStr + "  (Secure Boot / TPM controlled)") -ForegroundColor DarkGray
Write-Host ""

# ── Scheduled Tasks ───────────────────────────────────────────────
Write-Host "  [Scheduled Tasks]" -ForegroundColor Yellow

$taskDefs = @(
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cache Maintenance'; BKey='CacheMaintenance';    Label='Cache Maintenance'    }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cleanup';           BKey='Cleanup';             Label='Cleanup'              }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Scheduled Scan';    BKey='ScheduledScan';       Label='Scheduled Scan'       }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Verification';      BKey='Verification';        Label='Verification'         }
    @{ Path='\Microsoft\Windows\AccountHealth\';    Name='RecoverabilityToastTask';            BKey='RecoverabilityToast'; Label='RecoverabilityToast'  }
)

if ($defenderOff) {
    foreach ($taskDef in $taskDefs) {
        Check ($taskDef.Label + ' - Disabled') (TaskDisabled $taskDef.Path $taskDef.Name)
    }
} else {
    foreach ($taskDef in $taskDefs) {
        # $null -ne on the left: comparing array to $null on the right is a silent bug in PS.
        $wasEnabled = if ($backup -and $null -ne $backup.ScheduledTasks.($taskDef.BKey)) {
            [bool]$backup.ScheduledTasks.($taskDef.BKey)
        } else { $true }

        $isEnabled = -not (TaskDisabled $taskDef.Path $taskDef.Name)

        if ($wasEnabled) {
            Check ($taskDef.Label + ' - Enabled') $isEnabled
        } else {
            Check ($taskDef.Label + ' - Disabled (was disabled before)') (-not $isEnabled)
        }
    }
}
Write-Host ""

# ── EPP Context Menu ──────────────────────────────────────────────
$eppSubkeys = @(
    'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
)
$eppBackupKeys = @('Star', 'Drive', 'Directory', 'DirBg', 'Folder')
$eppLabels     = @('Classes\*\...EPP', 'Classes\Drive\...EPP', 'Classes\Directory\...EPP', 'Classes\Dir\Bg\...EPP', 'Classes\Folder\...EPP')

if ($defenderOff) {
    Write-Host "  [EPP Context Menu - absent = OK]" -ForegroundColor Yellow
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        Check ($eppLabels[$i] + ' - removed') (KeyAbsent $eppSubkeys[$i])
    }
} else {
    Write-Host "  [EPP Context Menu]" -ForegroundColor Yellow
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        $wasPresent = if ($backup) { $null -ne $backup.EppContextMenu.($eppBackupKeys[$i]) } else { $true }
        $isAbsent   = KeyAbsent $eppSubkeys[$i]

        if ($wasPresent) {
            Check ($eppLabels[$i] + ' - present') (-not $isAbsent)
        } else {
            if ($isAbsent) {
                CheckOK ($eppLabels[$i] + ' - absent (was absent before)')
            } else {
                Check ($eppLabels[$i] + ' - should be absent (was absent before)') $false
            }
        }
    }
}
Write-Host ""

# ── Security Center Notifications ────────────────────────────────
Write-Host "  [Security Center Notifications]" -ForegroundColor Yellow
if ($defenderOff) {
    Check 'AntiVirusDisableNotify = 1'       (RegValue 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify' 1)
    Check 'AntiVirusOverride = 1'            (RegValue 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride' 1)
    Check 'SecurityAndMaintenance toast Off' (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled' 0)
} else {
    $scBackup     = if ($backup) { $backup.SecurityCenter } else { $null }
    $avDNBackup   = if ($scBackup) { $scBackup.AntiVirusDisableNotify } else { $null }
    $avOvBackup   = if ($scBackup) { $scBackup.AntiVirusOverride      } else { $null }
    $toastBackup  = if ($scBackup) { $scBackup.ToastNotifyEnabled     } else { $null }
    CheckRestoredDword 'AntiVirusDisableNotify'       'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify' $avDNBackup
    CheckRestoredDword 'AntiVirusOverride'            'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride'      $avOvBackup
    CheckRestoredDword 'SecurityAndMaintenance toast' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled' $toastBackup
}
Write-Host ""

# ── SmartScreen ───────────────────────────────────────────────────
Write-Host "  [SmartScreen]" -ForegroundColor Yellow
if ($defenderOff) {
    Check 'EnableSmartScreen = 0'          (RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'         'EnableSmartScreen'          0)
    Check 'SmartScreenEnabled = Off'       (RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'         'Off')
    Check 'EnableWebContentEvaluation = 0' (RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost'  'EnableWebContentEvaluation'  0)
} else {
    $ssBackup        = if ($backup) { $backup.SmartScreen } else { $null }
    $ssPolicyBackup  = if ($ssBackup) { $ssBackup.PolicyValue   } else { $null }
    $ssExplorerBackup= if ($ssBackup) { $ssBackup.ExplorerValue } else { $null }
    $ssAppHostBackup = if ($ssBackup) { $ssBackup.AppHostValue  } else { $null }
    CheckRestoredDword 'EnableSmartScreen'          'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'         'EnableSmartScreen'          $ssPolicyBackup
    CheckRestoredSz    'SmartScreenEnabled'         'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'         $ssExplorerBackup
    CheckRestoredDword 'EnableWebContentEvaluation' 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost'  'EnableWebContentEvaluation'  $ssAppHostBackup
}
Write-Host ""

# ── Tray / Health Center ──────────────────────────────────────────
Write-Host "  [Tray / Health Center]" -ForegroundColor Yellow
if ($defenderOff) {
    Check 'HideSystray = 1'         (RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray' 1)
    Check 'DisableHealthCenter = 1' (RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HealthCenter' 'DisableHealthCenter' 1)
} else {
    $stBackup         = if ($backup) { $backup.Systray } else { $null }
    $hideSystrayBackup  = if ($stBackup) { $stBackup.HideSystray        } else { $null }
    $healthCenterBackup = if ($stBackup) { $stBackup.DisableHealthCenter } else { $null }
    CheckRestoredDword 'HideSystray'         'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray'         $hideSystrayBackup
    CheckRestoredDword 'DisableHealthCenter' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HealthCenter'                     'DisableHealthCenter'  $healthCenterBackup
}
Write-Host ""

# ── Autostart ─────────────────────────────────────────────────────
Write-Host "  [Autostart]" -ForegroundColor Yellow
if ($defenderOff) {
    Check 'SecurityHealth - removed from Run' (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth')
} else {
    $shEntry = if ($backup) { $backup.SecurityHealthAutorun } else { $null }
    # Backward compatibility: old backup format stored a plain string, new format stores {Value, Type}
    $shValue = if ($shEntry -is [string]) { $shEntry } elseif ($shEntry) { $shEntry.Value } else { $null }
    if ($null -eq $shValue) {
        if (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth') {
            CheckOK 'SecurityHealth - absent'
        } else {
            Check 'SecurityHealth - should be absent' $false
        }
    } else {
        Check 'SecurityHealth - present in Run' (-not (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth'))
    }
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────
$totalChecks = $script:PassCount + $script:FailCount
Sep
if ($script:FailCount -eq 0) {
    Write-Host ("  ALL OK " + $script:PassCount + "/" + $totalChecks) -ForegroundColor Green
} else {
    Write-Host ("  OK: " + $script:PassCount + "/" + $totalChecks + "   DIFF: " + $script:FailCount) -ForegroundColor Yellow
    if ($defenderOff) {
        Write-Host "  [DIFF] items were not applied or were reverted." -ForegroundColor Red
    } else {
        Write-Host "  [DIFF] items were not fully restored." -ForegroundColor Red
    }
}
Write-Host ""
pause
