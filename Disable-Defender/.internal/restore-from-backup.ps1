<#
  restore-from-backup.ps1
  Restores Defender settings from defender-backup.json created by stage-normal.ps1.
  If backup is missing or a value was null, uses safe defaults.
  Run via Defender.cmd /Restore (UAC elevation is automatic).
#>

param(
    # No prompts: explanatory pauses are skipped and ambiguous choices take
    # their safe default (decline rather than silently apply defaults) --
    # for scripted and VM-test runs, same purpose as stage-normal.ps1's switch.
    [switch]$Unattended
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'service-defaults.ps1')
. (Join-Path $PSScriptRoot 'backup-state.ps1')
. (Join-Path $PSScriptRoot 'operation-state.ps1')
. (Join-Path $PSScriptRoot 'console-ui.ps1')
. (Join-Path $PSScriptRoot 'restore-verification.ps1')
. (Join-Path $PSScriptRoot 'run-lock.ps1')
. (Join-Path $PSScriptRoot 'safe-mode-entry.ps1')

Set-LogFilePath (Join-Path $PSScriptRoot 'defender-log.txt')

# Helpers

function Invoke-RegistrySecurityRestore {
    param([bool]$UseDefaults)
    $defaultArguments = @()
    if ($UseDefaults) { $defaultArguments += '-UseDefaults' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore @defaultArguments *> $null
    return $LASTEXITCODE
}

function Restore-Val($backupVal, $defaultVal) {
    if ($null -ne $backupVal) { return $backupVal }
    return $defaultVal
}

# Live registry read -- exercised by the VM interrupted/full-cycle runs, not an
# isolated unit test: no fake data stands in for a real ControlSet\Services key.
# Returns one entry per (service, ControlSet) pair found, carrying enough to look
# up that pair's backed-up original value later -- a flat list of Start values
# alone cannot tell "this service" from "this service in this ControlSet".
function Get-ServiceStartEntries {
    param([string[]]$ServiceNames, [string[]]$ControlSetNames)
    $entries = @()
    foreach ($csName in $ControlSetNames) {
        foreach ($svcName in $ServiceNames) {
            $registryKey = $null
            try {
                $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName\Services\$svcName")
                if ($null -eq $registryKey) { continue }  # key absent in this ControlSet -- not an error
                $entries += [pscustomobject]@{
                    ServiceName    = $svcName
                    ControlSetName = $csName
                    Start          = $registryKey.GetValue('Start')
                }
            } finally {
                if ($null -ne $registryKey) { $registryKey.Close() }
            }
        }
    }
    # Unary comma: a 1-element array returned bare unrolls to its lone
    # [pscustomobject] on the way out (unlike a value-type element, a
    # PSCustomObject has no synthetic .Count -- callers checking .Count on
    # exactly one entry would see $null, not 1).
    return ,$entries
}

# v3 backups store a value per ControlSet name; v2/legacy backups store one value
# applied to every ControlSet -- Assert-BackupServiceStart enforces this shape.
# Shared by Test-ProtectionStepsNeeded and Invoke-RestoreSettingsStep so both
# read a service's backed-up Start value the same way.
function Get-BackupServiceStartValue {
    param($Backup, [string]$ServiceName, [string]$ControlSetName)
    $backupValue = if ($Backup) { $Backup.Services.$ServiceName } else { $null }
    if ($backupValue -is [System.Management.Automation.PSCustomObject]) {
        return $backupValue.$ControlSetName
    }
    return $backupValue
}

# Pure decision, no registry access -- whether any tracked (service, ControlSet)
# pair is in the disabled state (Start=4) AND that is not its backed-up original
# value, in ANY ControlSet. Checking only WinDefend here let a partial restore
# (WinDefend fixed, e.g. MDCoreSvc still 4) report "nothing left to do" on the
# next run and silently skip the rest of Invoke-RestoreSettingsStep's services
# block. Comparing against the backup (rather than flagging every Start=4) keeps
# a service the user had disabled before this tool ever ran from being treated
# as something stage-safe.ps1 changed and needing ownership/ACL steps it never touched.
function Test-ProtectionStepsNeeded {
    param($Entries, $Backup, [hashtable]$ServiceDefaults)
    foreach ($entry in $Entries) {
        if ($null -eq $entry.Start -or [int]$entry.Start -ne 4) { continue }
        $backupStartValue = Get-BackupServiceStartValue -Backup $Backup -ServiceName $entry.ServiceName -ControlSetName $entry.ControlSetName
        $expectedStartValue = [int](Restore-Val $backupStartValue $ServiceDefaults[$entry.ServiceName])
        if ($expectedStartValue -ne 4) { return $true }
    }
    return $false
}

function Restore-RegistryValue($path, $name, $val, [Microsoft.Win32.RegistryValueKind]$kind) {
    $pathParts = $path -split '\\', 2
    $hive = switch ($pathParts[0]) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported restore registry path: $path" }
    }
    if ($pathParts.Count -ne 2 -or $pathParts[1] -eq '') { throw "Missing registry subkey: $path" }
    $registryKey = $null
    try {
        $registryKey = $hive.OpenSubKey($pathParts[1], $true)
        if ($null -eq $val -or $val -is [System.DBNull]) {
            # Missing keys and values are acceptable; access failures still throw.
            if ($null -ne $registryKey) { $registryKey.DeleteValue($name, $false) }
            return
        }
        if ($null -eq $registryKey) { $registryKey = $hive.CreateSubKey($pathParts[1], $true) }
        $registryKey.SetValue($name, $val, $kind)
    } finally {
        if ($null -ne $registryKey) { $registryKey.Close() }
    }
}
function Restore-Dword($path, $name, $val) {
    if ($null -ne $val -and $val -isnot [System.DBNull]) { $val = [int]$val }
    Restore-RegistryValue $path $name $val DWord
}
function Restore-Sz($path, $name, $val) {
    Restore-RegistryValue $path $name $val String
}

# Restores the catalog entries of one backup section from the backup; a value
# the backup does not hold is removed, not replaced by a default.
function Restore-ProtectedRegistrySection {
    param($Backup, [string]$Section, [bool]$RestoreUserSettings)
    foreach ($entry in @(Get-ProtectedRegistryValues -IncludeUser:$RestoreUserSettings)) {
        if ($entry.Section -ne $Section) { continue }
        if ($Section -eq 'AttachmentWarning' -and $Backup -and $null -eq $Backup.AttachmentWarning) { continue }
        # A field added to an existing section later (the two
        # Notifications keys) is genuinely absent -- not recorded as null --
        # on a backup from before it existed; such a backup has no authority
        # over that value, so it must be left untouched, not deleted.
        if ($Backup -and $Backup.$Section -and $script:LegacyOptionalSectionFields -and $script:LegacyOptionalSectionFields.ContainsKey($Section) -and
            $entry.Field -in $script:LegacyOptionalSectionFields[$Section] -and
            $Backup.$Section.PSObject.Properties.Name -notcontains $entry.Field) { continue }
        $path = Get-ProtectedRegistryNativePath $entry
        $value = Get-RestoreRegistryExpectedValue $Backup $entry
        if ($entry.Kind -eq 'String') { Restore-Sz $path $entry.Name $value } else { Restore-Dword $path $entry.Name $value }
    }
}

# Load & validate backup
# A truncated or manually edited JSON produces an explicit [ERROR] rather
# than a silent $null fallback that would silently apply hardcoded defaults.
# Throws on validation failure or a declined recovery -- the caller's
# try/catch exits 1.
function Get-RestoreBackup {
    param([string]$BackupPath, [switch]$Unattended)

    $backup = $null
    $restoreUserSettings = $true
    $alreadyConfirmed = $false

    if (Test-Path $BackupPath) {
        try {
            $backup = Read-BackupState $BackupPath -AllowOtherUser
            if ($backup.Identity -and $backup.Identity.UserSid -ne (Get-BackupIdentity).UserSid) {
                $restoreUserSettings = $false
                Write-WarningLine 'Backup belongs to another account on this Windows installation.'
                Write-Host "  System settings will be restored; this account's settings will be left unchanged." -ForegroundColor Yellow
            }
            $backupTimestamp = [datetime]::Parse($backup.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd HH:mm')
            Write-Host ("  Backup: " + $backupTimestamp) -ForegroundColor DarkGray
        } catch [InvalidOperationException] {
            Write-ErrorLine "$_"
            Write-Host "  Restoration cancelled. Use a backup from this Windows installation." -ForegroundColor Yellow
            if (-not $Unattended) { Invoke-ReadKey *> $null }
            throw
        } catch {
            Write-ErrorLine "Backup validation failed: $_"
            Write-Host "  The original settings cannot be recovered from this file." -ForegroundColor Yellow
            # Unattended takes the safe default here too: it declines rather than
            # silently normalizing a corrupted backup into hardcoded defaults.
            if ($Unattended) {
                Write-Host "  [Unattended] Declining; existing backup preserved." -ForegroundColor DarkGray
                throw
            }
            Write-Host "  Apply built-in defaults instead? This is not an exact rollback. (Y/N): " -NoNewline -ForegroundColor Yellow
            $answer = Invoke-ReadKey
            Write-Host $answer
            if ($answer -notin @('y', 'Y')) { throw }
            $backup = $null
            $alreadyConfirmed = $true
            Write-Host "  Existing backup preserved. Save all open files before continuing." -ForegroundColor Yellow
            Invoke-ReadKey *> $null
        }
    }

    Write-Host ""
    if (-not $backup -and -not $alreadyConfirmed) {
        Write-WarningLine 'No backup available: applying standard settings, not an exact rollback.'
    }
    return [pscustomobject]@{ Backup = $backup; RestoreUserSettings = $restoreUserSettings; AlreadyConfirmed = $alreadyConfirmed }
}

# [1/3] Take ownership
# Throws on failure -- the caller's try/catch exits 1.
function Invoke-TakeOwnershipStep {
    param([bool]$UseDefaults, [switch]$Unattended)
    # The external powershell.exe call runs before the console line is printed --
    # starting the line with -NoNewline and only then shelling out can leave the
    # terminating OK/FAIL on its own line when this script's own output is itself
    # redirected (observed in VM test logs; a real console was not confirmed
    # affected, but nothing here depends on seeing the line mid-step, so printing
    # it whole once the result is known removes the risk either way).
    # Write-StepPending still logs the attempt before that call, so a hang or
    # crash in it leaves a trace instead of silently skipping the step.
    Write-StepPending '[1/3] Taking registry ownership'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action take *> $null
    Write-StepPrint '[1/3] Taking registry ownership'
    if ($LASTEXITCODE -ne 0) {
        Write-StepFail
        Write-Host ""
        Write-ErrorLine 'Failed to take ownership. Run as Administrator.'
        if ((Invoke-RegistrySecurityRestore $UseDefaults) -ne 0) {
            Write-Warning 'Could not restore registry security after the failed operation.'
        }
        Write-Host ""
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw "Failed to take registry ownership"
    }
    Write-StepOk
}

# [2/3] Restore all settings
# Throws on failure -- the caller's try/catch exits 1.
function Invoke-RestoreSettingsStep {
    param($backup, [bool]$restoreUserSettings, [hashtable]$serviceDefaults, [string[]]$ServiceNames, [bool]$ProtectionStepsNeeded, [switch]$Unattended)
    Write-StepStart '[2/3] Restoring Defender settings'
    try {
    # Tamper Protection blocks service writes while Defender runs, even when restoring the same value.
    if ($ProtectionStepsNeeded) {
    # Restore Start value in ALL concrete ControlSets (001, 002, etc.) plus the alias.
    # stage-safe.ps1 wrote to all of them when disabling -- we must mirror that here,
    # otherwise Windows may boot from ControlSet001/002 with Start=4 still set.
    $restoreControlSets = Get-ControlSetTargets

    foreach ($svcName in $ServiceNames) {
        foreach ($csName in $restoreControlSets) {
            $backupStartValue = Get-BackupServiceStartValue -Backup $backup -ServiceName $svcName -ControlSetName $csName
            if ((Test-BackupServiceAbsenceRecorded $backup $svcName $csName) -and (Test-ServiceAppearedAfterDisable "HKLM\SYSTEM\$csName\Services\$svcName")) { continue }
            $targetStartValue = [int](Restore-Val $backupStartValue $serviceDefaults[$svcName])
            $registryKey = $null
            try {
                $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "SYSTEM\$csName\Services\$svcName", $true)
                if ($null -eq $registryKey) { continue }  # key absent in this ControlSet -- not an error
                # [RegistryValueKind]::DWord enum is required -- passing the string 'DWord' silently writes REG_SZ.
                $registryKey.SetValue('Start', $targetStartValue, [Microsoft.Win32.RegistryValueKind]::DWord)
            } catch {
                Write-Host ""
                Write-ErrorLine "Failed to restore '$svcName' in $csName`: $_"
                throw
            } finally {
                if ($null -ne $registryKey) { $registryKey.Close() }
            }
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
        # A recorded $null (key present, value null) means the task did not exist
        # on the original machine -- Assert-RestoredTasks already treats this as
        # "must stay absent"; Enable/Disable-ScheduledTask on a task that was
        # never created throws, so restoration must skip it the same way, not
        # fall back to the legacy "key missing entirely -- assume enabled" default.
        $taskRecorded = $backup -and ($backup.ScheduledTasks.PSObject.Properties.Name -contains $taskDef.Key)
        $taskValue = if ($taskRecorded) { $backup.ScheduledTasks.($taskDef.Key) } else { $null }
        if ($taskRecorded -and $null -eq $taskValue) { continue }
        $wasEnabled = if ($null -ne $taskValue) { [bool]$taskValue } else { $true }
        try {
            if ($wasEnabled) {
                Enable-ScheduledTask -TaskPath $taskDef.Path -TaskName $taskDef.Name -ErrorAction Stop *> $null
            } else {
                # The backup recorded the task as disabled -- it may since have been
                # re-enabled (by the user or Windows), so restoring to that state
                # requires disabling it here too, not just skipping Enable.
                Disable-ScheduledTask -TaskPath $taskDef.Path -TaskName $taskDef.Name -ErrorAction Stop *> $null
            }
        } catch {
            $verb = if ($wasEnabled) { 'enable' } else { 'disable' }
            Write-ErrorLine "Could not $verb scheduled task '$($taskDef.Name)': $_"
            throw
        }
    }

    # Security Center / SmartScreen / downloaded-file warning / tray
    Restore-ProtectedRegistrySection $backup 'SecurityCenter' $restoreUserSettings
    Restore-ProtectedRegistrySection $backup 'SmartScreen' $restoreUserSettings
    Restore-ProtectedRegistrySection $backup 'AttachmentWarning' $restoreUserSettings

    # Remove ACL deny on smartscreen.exe set by stage-safe.ps1
    # Test-Path guard: smartscreen.exe is absent on Windows Server Core.
    $smartscreenExe = "$env:SystemRoot\System32\smartscreen.exe"
    if ($backup -and $backup.SchemaVersion -ge 4) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore-file
        if ($LASTEXITCODE -ne 0) { throw 'Failed to restore SmartScreen security descriptor.' }
    } elseif (Test-Path $smartscreenExe) {
        Write-Warning 'Legacy backup: the original SmartScreen owner and ACL are unavailable; applying the legacy repair.'
        takeown /f "$smartscreenExe" /a *> $null
        if ($LASTEXITCODE -ne 0) { throw "takeown on smartscreen.exe failed (exit $LASTEXITCODE)." }
        icacls "$smartscreenExe" /remove:d "*S-1-5-32-545" *> $null
        if ($LASTEXITCODE -ne 0) { throw "icacls on smartscreen.exe failed (exit $LASTEXITCODE)." }
    }

    Restore-ProtectedRegistrySection $backup 'Systray' $restoreUserSettings

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
        $backupGuid = if ($null -eq $backup) { $defaultEppGuid } else { $backup.EppContextMenu.($eppEntry.Key) }
        if ($null -eq $backupGuid) {
            # Key was absent before -- remove it
            $parentPath = $eppEntry.Value.Substring(0, $eppEntry.Value.LastIndexOf('\'))
            $childName  = $eppEntry.Value.Substring($eppEntry.Value.LastIndexOf('\') + 1)
            $parentKey  = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree($childName, $false) }
            } catch {
                Write-ErrorLine "Could not remove EPP key '$($eppEntry.Key)': $_"
                throw
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
                Write-ErrorLine "Could not restore EPP key '$($eppEntry.Key)': $_"
                throw
            } finally {
                if ($null -ne $eppKey) { $eppKey.Close() }
            }
        }
    }

    # SecurityHealth autorun
    $shEntry = if ($backup) { $backup.SecurityHealthAutorun } else { @{ Value='%windir%\system32\SecurityHealthSystray.exe'; Type='ExpandString' } }
    # Backward compatibility: old backup format stored a plain string, new format stores {Value, Type}
    if ($shEntry -is [string]) {
        $shValue = $shEntry
        $shType  = $null
    } else {
        $shValue = if ($shEntry) { $shEntry.Value } else { $null }
        $shType  = if ($shEntry -and $shEntry.Type) { $shEntry.Type } else { $null }
    }
    # Use backed-up type if available; infer it only for legacy values.
    $regType = if ($shType -eq 'ExpandString') { 'ExpandString' }
               elseif ($shType -eq 'String')   { 'String' }
               elseif ($shValue -like '*%*')    { 'ExpandString' }
               else                             { 'String' }
    Restore-RegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth' $shValue $regType

    Write-StepOk
    } catch {
        Write-StepFail
        Write-Host ""
        Write-ErrorLine "Failed to restore one or more settings:"
        Write-Host "  $_" -ForegroundColor Yellow
        Write-LogLine "  $_"
        Write-Host ""
        Write-Host "  Defender may not be fully restored. Check the output above." -ForegroundColor Yellow
        if ((Invoke-RegistrySecurityRestore ($null -eq $backup)) -ne 0) {
            Write-Warning 'Could not restore registry security after the failed operation.'
        }
        Write-Host ""
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw
    }
}

# [3/3] Restore ownership
# A failed security rollback must retain the unfinished-operation marker.
function Invoke-RestoreOwnershipStep {
    param([bool]$UseDefaults)
    # See Invoke-TakeOwnershipStep above -- same reason the shell-out runs before
    # the line starts, and Write-StepPending logs the attempt first for the same
    # reason.
    Write-StepPending '[3/3] Restoring registry security'
    $registrySecurityExit = Invoke-RegistrySecurityRestore $UseDefaults
    Write-StepPrint '[3/3] Restoring registry security'
    if ($registrySecurityExit -ne 0) {
        Write-StepWarn
        Write-Host ""
        Write-WarningLine 'Failed to restore registry security.'
        Write-Host "  Registry owner or permissions may differ from the saved state." -ForegroundColor DarkGray
        Write-Host "  Reboot and re-run Defender.cmd /Restore to retry." -ForegroundColor DarkGray
        Write-Host ""
        throw "Failed to restore registry security (exit $registrySecurityExit)."
    } else {
        Write-StepOk
    }
}

# Header
Sep
Write-Host "  Defender Restore  --  Full Rollback" -ForegroundColor Cyan
Sep
Write-Host ""

$runLockPath = Get-RunLockPath
$runLock = Enter-RunLock $runLockPath
if ($null -eq $runLock) {
    Write-Host "  [!] Another Disable/Restore run is already in progress." -ForegroundColor Red
    Write-Host "      Exiting without making any change." -ForegroundColor DarkGray
    exit 1
}

$operationStatePath = Join-Path $PSScriptRoot 'operation-state.json'
$previousOperation   = Get-OperationState $operationStatePath
if ($null -ne $previousOperation) {
    if ($previousOperation.Readable) {
        Write-Host "  [!] Unfinished $($previousOperation.Operation) operation found (stage: $($previousOperation.Stage), started $($previousOperation.StartedAt))." -ForegroundColor Yellow
    } else {
        Write-Host "  [!] An unfinished-operation marker exists but could not be read." -ForegroundColor Yellow
    }
    Write-Host "      Restoring now may run alongside a pending Safe Mode step from that operation." -ForegroundColor DarkGray
    Write-Host ""
}
$backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
try {
    $restoreBackupResult = Get-RestoreBackup -BackupPath $backupPath -Unattended:$Unattended
} catch {
    exit 1
}
$backup = $restoreBackupResult.Backup
$restoreUserSettings = $restoreBackupResult.RestoreUserSettings
$alreadyConfirmed = $restoreBackupResult.AlreadyConfirmed

# Preflight: warn if no backup and Defender is active

if (-not $backup -and -not $alreadyConfirmed) {
    # Only a service that is not there counts as not running; a failed query
    # takes the cautious side and asks, since skipping the question applies
    # defaults over a possibly active Defender.
    $defenderRunning = try {
        (Get-Service -Name WinDefend -ErrorAction Stop).Status -eq 'Running'
    } catch {
        $_.FullyQualifiedErrorId -notlike 'NoServiceFoundForGivenName*'
    }
    if ($defenderRunning) {
        Write-WarningLine 'No backup file (defender-backup.json) found.'
        Write-Host "            Windows Defender appears to be already active." -ForegroundColor DarkGray
        Write-Host "            Differences from standard settings have not been checked." -ForegroundColor DarkGray
        Write-Host ""
        if ($Unattended) {
            Write-Host "  [Unattended] Declining by default. Exiting." -ForegroundColor DarkGray
            Write-Host ""
            exit 0
        }
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

# Service names used by restore.
$defenderServiceNames = @(
    'WinDefend','WdFilter','MDCoreSvc','WdBoot','WdNisSvc','WdNisDrv',
    'Sense','webthreatdefsvc','webthreatdefusersvc','wscsvc'
)

# Live Tamper Protection blocks service writes; compare every ControlSet with the backup before restoring.
# A service disabled before this tool ran must not trigger unnecessary ownership changes.
try {
    $serviceStartEntries = Get-ServiceStartEntries -ServiceNames $defenderServiceNames -ControlSetNames (Get-ControlSetTargets)
} catch {
    Write-ErrorLine "Could not determine which protection settings need restoration: $($_.Exception.Message)"
    Write-Host "  Restoration cancelled before changing settings." -ForegroundColor Yellow
    exit 1
}
$protectionStepsNeeded = Test-ProtectionStepsNeeded -Entries $serviceStartEntries -Backup $backup -ServiceDefaults $serviceDefaults

# Retry protection steps only when the marker indicates changes may have occurred or is unreadable.
# Forcing ownership changes before Safe Mode ran can fail under live Tamper Protection.
if ($null -ne $previousOperation) {
    $isUntouchedProtectionStage = $previousOperation.Readable -and (
        ($previousOperation.Operation -eq 'Disable' -and $previousOperation.Stage -in @('NormalStarted', 'NormalDone')) -or
        ($previousOperation.Operation -eq 'Restore' -and $previousOperation.Stage -eq 'RestoreSettingsOnly')
    )
    if (-not $isUntouchedProtectionStage) { $protectionStepsNeeded = $true }
}

# Reapply restoration after confirmation: checking only some settings cannot prove full rollback.

# Confirm before making any changes
if (-not $alreadyConfirmed -and -not $Unattended) {
    Write-Host "  Save all open files.  Press any key to continue or close to cancel..." -ForegroundColor Yellow
    Invoke-ReadKey *> $null
    Write-Host ""
}

if (-not $backup -or $backup.SchemaVersion -lt 4) {
    Write-Warning 'Legacy backup: original registry owner and ACL were not saved; exact security restoration is unavailable.'
}

# A Disable run that reached NormalDone or SafeModeStarted but never cleared its
# marker left this RunOnce entry behind -- if it fires on the reboot this script
# ends with, it would re-disable Defender right after restoring it.
try {
    Restore-RegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' '*LauncherSafe' $null String
} catch {
    Write-ErrorLine "Could not cancel the pending Safe Mode step: $($_.Exception.Message)"
    Write-Host "  Restoration cancelled; the pending step could disable protection after reboot." -ForegroundColor Yellow
    exit 1
}

# A Disable run interrupted after it prepared the Safe Mode boot but before the
# reboot leaves that boot entry behind, and nothing would remove it once the
# RunOnce entry is gone. The flag on the running entry is what earlier versions
# set; bcdedit returns non-zero when it is already absent, which is the normal
# case, so that exit code is intentionally not checked.
bcdedit /deletevalue "{current}" safeboot *> $null
try {
    Remove-SafeModeBootEntry
} catch {
    Write-WarningLine "Could not remove the temporary Safe Mode boot entry: $($_.Exception.Message)"
}

# Stage records whether THIS run is about to touch ownership/ACL at all --
# RestoreSettingsOnly when $protectionStepsNeeded is false means a retry
# interrupted after this point must not force [1/3] back on (see the
# isUntouchedProtectionStage check above); RestoreStarted means it may have,
# so a retry should.
$restoreStage = if ($protectionStepsNeeded) { 'RestoreStarted' } else { 'RestoreSettingsOnly' }
Set-OperationState $operationStatePath 'Restore' $restoreStage

# [1/3] Take ownership
try {
    if ($protectionStepsNeeded) {
        Invoke-TakeOwnershipStep -UseDefaults ($null -eq $backup) -Unattended:$Unattended
    } else {
        Write-Host "  [1/3] Taking registry ownership... SKIPPED" -ForegroundColor DarkGray
        Write-Host "        Defender is not currently disabled -- ownership was never changed." -ForegroundColor DarkGray
    }

    Invoke-RestoreSettingsStep -backup $backup -restoreUserSettings $restoreUserSettings -serviceDefaults $serviceDefaults -ServiceNames $defenderServiceNames -ProtectionStepsNeeded $protectionStepsNeeded -Unattended:$Unattended

    if ($protectionStepsNeeded) {
        Invoke-RestoreOwnershipStep -UseDefaults ($null -eq $backup)
    } else {
        Write-Host "  [3/3] Restoring registry security... SKIPPED" -ForegroundColor DarkGray
    }

    Assert-RestoredSettings -Backup $backup -RestoreUserSettings $restoreUserSettings -ServiceDefaults $serviceDefaults
    Clear-OperationState $operationStatePath
    # Done
    Write-Host ""
    Sep
    Write-Host "  Done. Rebooting..." -ForegroundColor Green
    Sep
    Write-Host ""
    Write-Host "  Settings verified. After reboot, run Defender.cmd /Status to check the resulting state." -ForegroundColor DarkGray
    Write-Host "  Press any key to reboot..." -ForegroundColor Yellow
    if (-not $Unattended) { Invoke-ReadKey *> $null }

    # A missing shutdown.exe (Embedded / LTSB / Server Core) throws under 'Stop'
    # instead of setting $LASTEXITCODE, so the lookup failure is caught here to
    # reach the cmdlet fallback.
    $restartStarted = $false
    try {
        shutdown /r /t 0
        $restartStarted = ($LASTEXITCODE -eq 0)
    } catch {
        $restartStarted = $false
    }
    if (-not $restartStarted) { Restart-Computer -Force }
} catch {
    Write-ErrorLine "Restoration did not complete: $($_.Exception.Message)"
    Write-LogLocation
    exit 1
}
