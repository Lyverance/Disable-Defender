# Check-Status.ps1 -- Defender state verification (works both ways: disabled-check and restore-check)

param(
    # No prompts: the closing pause is skipped so automated callers (entry.ps1's
    # /Status /Unattended, VM test drivers) do not hang waiting for a keypress --
    # same purpose as stage-normal.ps1/restore-from-backup.ps1's switch.
    [switch]$Unattended
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'service-defaults.ps1')
. (Join-Path $PSScriptRoot 'backup-state.ps1')
. (Join-Path $PSScriptRoot 'operation-state.ps1')
. (Join-Path $PSScriptRoot 'console-ui.ps1')
. (Join-Path $PSScriptRoot 'status-security.ps1')
. (Join-Path $PSScriptRoot 'status-output.ps1')
. (Join-Path $PSScriptRoot 'status-checks.ps1')

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $relaunchArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Unattended) { $relaunchArgs += ' -Unattended' }
    $elevated = Start-Process powershell.exe -ArgumentList $relaunchArgs -Verb RunAs -Wait -PassThru
    exit $elevated.ExitCode
}

$script:PassCount = 0
$script:FailCount = 0
$script:SectionItems = @()

trap {
    Write-Host ""
    Write-Host "  [FATAL ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "  Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
    Write-Host ""
    if (-not $Unattended) { pause }
    exit 1
}

# Load backup (for restore-mode comparison)
$backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
$checkUserSettings = $true
$limitedComparison = $false
$backup     = $null
if (Test-Path $backupPath) {
    try {
        $backup = Read-BackupState $backupPath -AllowOtherUser
        $unrecordedEntries = @(Get-ProtectedRegistryValues -IncludeUser | Where-Object { -not (Test-RegistryEntryRecorded $backup $_) })
        if ($unrecordedEntries.Count -gt 0) {
            $limitedComparison = $true
            Write-Host "  [WARNING] Backup predates some settings; their original values cannot be checked." -ForegroundColor Yellow
        }
        if ($backup.Identity -and $backup.Identity.UserSid -ne (Get-BackupIdentity).UserSid) {
            $checkUserSettings = $false
            Write-Host "  [WARNING] Backup is from another account; checking system settings only." -ForegroundColor Yellow
        }
    } catch [InvalidOperationException] {
        Write-Host "  [ERROR] $_" -ForegroundColor Red
        if (-not $Unattended) { pause }
        exit 1
    } catch {
        Write-Host "  [ERROR] Backup validation failed: $_" -ForegroundColor Red
        Write-Host "  Cannot compare against the original state." -ForegroundColor Yellow
        if ($Unattended) { exit 1 }
        $answer = Read-Host '  Check current state without the original settings? (Y/N)'
        if ($answer -notin @('y', 'Y')) { exit 1 }
        $backup = $null
        $limitedComparison = $true
        Write-Host "  [WARNING] Limited check: original settings are unavailable; fallback expectations will be used." -ForegroundColor Yellow
    }
}

# Auto-detect mode
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
$operationStatePath = Join-Path $PSScriptRoot 'operation-state.json'
$previousOperation   = Get-OperationState $operationStatePath
if ($null -ne $previousOperation) {
    if ($previousOperation.Readable) {
        Write-Host ("  [!] Unfinished " + $previousOperation.Operation + " operation, stage: " + $previousOperation.Stage) -ForegroundColor Yellow
    } else {
        Write-Host "  [!] An unfinished-operation marker exists but could not be read." -ForegroundColor Yellow
    }
}
Sep
Write-Host ""

# No backup and Defender appears enabled: no baseline comparison was made
if (-not $defenderOff -and -not $backup -and -not $limitedComparison) {
    Write-Host "  Defender appears enabled and no backup was found." -ForegroundColor DarkGray
    Write-Host "  Differences from standard settings have not been checked." -ForegroundColor DarkGray
    Write-Host ""
    if (-not $Unattended) { pause }
    exit 0
}

# Services
if ($defenderOff) {
    Check 'WinDefend           - Disabled'  (ServiceDisabled 'WinDefend')
    Check 'WdFilter            - Disabled'  (ServiceDisabled 'WdFilter')
    Check 'MDCoreSvc           - Disabled'  (ServiceDisabled 'MDCoreSvc')
    Check 'WdNisSvc            - Disabled'  (ServiceDisabled 'WdNisSvc')
    Check 'WdNisDrv            - Disabled'  (ServiceDisabled 'WdNisDrv')
    Check 'Sense               - Disabled'  (ServiceDisabled 'Sense')
    Check 'webthreatdefsvc     - Disabled'  (ServiceDisabled 'webthreatdefsvc')
    Check 'webthreatdefusersvc - Disabled'  (ServiceDisabled 'webthreatdefusersvc')
} else {
    foreach ($svcName in @('WinDefend','WdFilter','MDCoreSvc','WdNisSvc','WdNisDrv','Sense','webthreatdefsvc','webthreatdefusersvc')) {
        $expectedStart = Get-ExpectedServiceStart $backup $svcName $serviceDefaults[$svcName]
        $serviceKey = $null
        try {
            $serviceKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$svcName")
            $serviceKeyExists = $null -ne $serviceKey
            $actualStart = if ($null -eq $serviceKey) { $null } else { $serviceKey.GetValue('Start', $null) }
        } catch {
            Check "$svcName - cannot read Start: $_" $false
            continue
        } finally {
            if ($null -ne $serviceKey) { $serviceKey.Close() }
        }
        if (-not $serviceKeyExists -and $null -ne $expectedStart -and (Test-RestoredServiceStatus $backup $svcName $false $actualStart $expectedStart)) {
            Check "$svcName - optional service absent; no original value recorded" $true
            continue
        }
        if (Test-ServiceInstalledAfterDisable $expectedStart $serviceKeyExists $actualStart) {
            Check "$svcName - installed after Disable; left as found (Start $actualStart)" $true
            continue
        }
        $expectedLabel = if ($null -eq $expectedStart) { 'absent (recorded in backup)' } else { "$expectedStart" }
        $actualLabel = if ($null -eq $actualStart) { 'absent' } else { "$actualStart" }
        Check "$svcName - Start expected: $expectedLabel; actual: $actualLabel" ($actualStart -eq $expectedStart)
    }
}

# wscsvc remains running; notification policies suppress the toast without changing its Start value.
$wscsvcExpected = Get-ExpectedServiceStart $backup 'wscsvc' $serviceDefaults['wscsvc']
$wscsvcKey = $null
$wscsvcReadable = $true
try {
    $wscsvcKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\wscsvc')
    $wscsvcActual = if ($null -eq $wscsvcKey) { $null } else { $wscsvcKey.GetValue('Start', $null) }
} catch {
    Check "wscsvc - cannot read Start: $_" $false
    $wscsvcReadable = $false
} finally {
    if ($null -ne $wscsvcKey) { $wscsvcKey.Close() }
}
if ($wscsvcReadable) {
    $wscsvcExpectedLabel = if ($null -eq $wscsvcExpected) { 'absent (recorded in backup)' } else { "$wscsvcExpected" }
    $wscsvcActualLabel = if ($null -eq $wscsvcActual) { 'absent' } else { "$wscsvcActual" }
    Check "wscsvc              - kept running, Start expected: $wscsvcExpectedLabel; actual: $wscsvcActualLabel" ($wscsvcActual -eq $wscsvcExpected)
}

Write-Section 'Services'
$wdBootStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot' -Name Start -ErrorAction SilentlyContinue).Start
$wdBootStr   = if ($null -ne $wdBootStart) { "$wdBootStart" } else { 'n/a' }
Write-Host ("  [INFO] WdBoot               - Start = " + $wdBootStr + "  (Secure Boot / TPM controlled)") -ForegroundColor DarkGray
Write-Host ""

# Scheduled Tasks
$taskDefs = @(
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cache Maintenance'; BKey='CacheMaintenance';    Label='Cache Maintenance'    }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Cleanup';           BKey='Cleanup';             Label='Cleanup'              }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Scheduled Scan';    BKey='ScheduledScan';       Label='Scheduled Scan'       }
    @{ Path='\Microsoft\Windows\Windows Defender\'; Name='Windows Defender Verification';      BKey='Verification';        Label='Verification'         }
    @{ Path='\Microsoft\Windows\AccountHealth\';    Name='RecoverabilityToastTask';            BKey='RecoverabilityToast'; Label='RecoverabilityToast'  }
)

if ($defenderOff) {
    foreach ($taskDef in $taskDefs) {
        CheckTaskState ($taskDef.Label + ' - Disabled') (TaskDisabled $taskDef.Path $taskDef.Name) $true
    }
} else {
    foreach ($taskDef in $taskDefs) {
        # $null -ne on the left: comparing array to $null on the right is a silent bug in PS.
        $wasEnabled = if ($backup -and $null -ne $backup.ScheduledTasks.($taskDef.BKey)) {
            [bool]$backup.ScheduledTasks.($taskDef.BKey)
        } else { $true }

        $taskDisabledResult = TaskDisabled $taskDef.Path $taskDef.Name

        if ($wasEnabled) {
            CheckTaskState ($taskDef.Label + ' - Enabled') $taskDisabledResult $false
        } else {
            CheckTaskState ($taskDef.Label + ' - Disabled (was disabled before)') $taskDisabledResult $true
        }
    }
}
Write-Section 'Scheduled Tasks'
Write-Host ""

# EPP Context Menu
$eppSubkeys = @(
    'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'
    'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
)
$eppBackupKeys = @('Star', 'Drive', 'Directory', 'DirBg', 'Folder')
$eppLabels     = @('Classes\*\...EPP', 'Classes\Drive\...EPP', 'Classes\Directory\...EPP', 'Classes\Dir\Bg\...EPP', 'Classes\Folder\...EPP')
$eppTitle      = if ($defenderOff) { 'EPP Context Menu (removed = OK)' } else { 'EPP Context Menu' }

if ($defenderOff) {
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        CheckAbsent $eppLabels[$i] (KeyAbsent $eppSubkeys[$i])
    }
} else {
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        $backupGuid = if ($backup) { $backup.EppContextMenu.($eppBackupKeys[$i]) } else { $null }

        if ($backup -and $null -eq $backupGuid) {
            # Recorded absence -- was never present, restore must not have added it.
            CheckAbsent ($eppLabels[$i] + ' (was absent before)') (KeyAbsent $eppSubkeys[$i])
        } elseif ($null -ne $backupGuid) {
            # Recorded GUID -- content must match, not just "something is there".
            CheckRestoredPresent $eppLabels[$i] (Read-RegKeyDefault $eppSubkeys[$i]) $backupGuid $null
        } else {
            # No usable backup (limited comparison) -- presence is all that can be judged.
            CheckPresent $eppLabels[$i] (KeyAbsent $eppSubkeys[$i])
        }
    }
}
Write-Section $eppTitle
Write-Host ""

# Security Center Notifications
CheckProtectedRegistrySection 'SecurityCenter' $defenderOff $backup $checkUserSettings
Write-Section 'Security Center Notifications'
Write-Host ""

# SmartScreen
CheckProtectedRegistrySection 'SmartScreen' $defenderOff $backup $checkUserSettings
Write-Section 'SmartScreen'
Write-Host ""

# Downloaded-file warning
CheckProtectedRegistrySection 'AttachmentWarning' $defenderOff $backup $checkUserSettings
Write-Section 'Downloaded-file warning'
Write-Host ""

# Disabled-state security
# Ownership and the execute-deny entry are independent Disable operations.
if ($defenderOff) {
    try {
        $smartScreenOwner = Get-SmartScreenOwnerSid
        if ($null -eq $smartScreenOwner) {
            CheckOK 'smartscreen.exe not present; security checks skipped'
            Write-Host '  [INFO] smartscreen.exe not present; security checks skipped.' -ForegroundColor Yellow
        } else {
            Check 'smartscreen.exe owner = Administrators (ownership taken)' ($smartScreenOwner -eq $script:AdministratorsSid)
            Check 'smartscreen.exe denies execute to Users' (Test-SmartScreenExecuteDenied)
        }
    } catch {
        Check ('smartscreen.exe ownership cannot be verified: ' + $_.Exception.Message) $false
    }
    Write-Section 'Disabled security'
    Write-Host ""
}

# Tray / Health Center
CheckProtectedRegistrySection 'Systray' $defenderOff $backup $checkUserSettings
Write-Section 'Tray / Health Center'
Write-Host ""

# Autostart
$autorunPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
if ($defenderOff) {
    CheckAbsent 'SecurityHealth' (RegAbsent $autorunPath 'SecurityHealth')
} else {
    $shEntry = if ($backup) { $backup.SecurityHealthAutorun } else { $null }
    # Backward compatibility: old backup format stored a plain string, new format stores {Value, Type}
    $shValue = if ($shEntry -is [string]) { $shEntry } elseif ($shEntry) { $shEntry.Value } else { $null }
    $shType  = if ($shEntry -is [string] -or -not $shEntry) { $null } else { $shEntry.Type }
    if ($null -eq $shValue) {
        CheckAbsent 'SecurityHealth' (RegAbsent $autorunPath 'SecurityHealth')
    } else {
        # Content must match the backed-up command and type, not just "something is there".
        CheckRestoredPresent 'SecurityHealth' (Read-RegEntry $autorunPath 'SecurityHealth') $shValue $shType
    }
}
Write-Section 'Autostart'
Write-Host ""

# Summary
if (-not $defenderOff) {
    Write-RestoredSecurityStatus $backup
    Write-Host ""
}

$totalChecks = $script:PassCount + $script:FailCount
if ($limitedComparison) {
    Write-Host "  [WARNING] These checks do not prove restoration of your original settings." -ForegroundColor Yellow
}
Sep
if ($script:FailCount -eq 0) {
    Write-Host ("  ALL OK " + $script:PassCount + "/" + $totalChecks) -ForegroundColor Green
} else {
    Write-Host ("  OK: " + $script:PassCount + "/" + $totalChecks + "   PARTIAL: " + $script:FailCount) -ForegroundColor Yellow
    if ($defenderOff) {
        Write-Host "  [PARTIAL] items were not applied or were reverted." -ForegroundColor Red
    } else {
        Write-Host "  [PARTIAL] items were not fully restored." -ForegroundColor Red
    }
}
Write-Host ""
if (-not $Unattended) { pause }
if ($script:FailCount -gt 0) { exit 1 }
