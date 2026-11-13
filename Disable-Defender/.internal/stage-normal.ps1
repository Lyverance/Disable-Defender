<#
  stage-normal.ps1
  Run in NORMAL mode as Administrator (via Defender.cmd /Disable).
  The script will reboot into Safe Mode at the end.
#>

param(
    # No prompts: already-disabled, third-party-AV and reboot confirmations
    # all take their safe default (skip/decline) instead of waiting on a key.
    [switch]$Unattended
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'backup-state.ps1')
. (Join-Path $PSScriptRoot 'operation-state.ps1')
. (Join-Path $PSScriptRoot 'console-ui.ps1')
. (Join-Path $PSScriptRoot 'step-runner.ps1')
. (Join-Path $PSScriptRoot 'run-lock.ps1')
. (Join-Path $PSScriptRoot 'autorun-state.ps1')
. (Join-Path $PSScriptRoot 'safe-mode-entry.ps1')

$script:HasErrors = $false
$operationStatePath = Join-Path $PSScriptRoot 'operation-state.json'
Set-LogFilePath (Join-Path $PSScriptRoot 'defender-log.txt')

# Helpers

# Backup helpers -- read current state before any changes are made.
# Reads Start per ControlSet target (see Get-ControlSetTargets) -- stage-safe.ps1 sets it
# on every concrete ControlSet, not just CurrentControlSet, so the backup must distinguish
# them too instead of assuming they all held the same value.
function Get-ServiceStartByControlSet($svcName, [string[]]$controlSetTargets) {
    # A service key that does not exist is a recorded absence ($null); a key that
    # cannot be opened or read throws, so a failed read never reaches the backup
    # as "the original value was absent".
    $startByControlSet = @{}
    foreach ($csName in $controlSetTargets) {
        $serviceKey = $null
        try {
            $serviceKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName\Services\$svcName")
            $startByControlSet[$csName] = if ($null -eq $serviceKey) { $null } else { $serviceKey.GetValue('Start', $null) }
        } finally { if ($null -ne $serviceKey) { $serviceKey.Close() } }
    }
    return $startByControlSet
}
function Get-TaskEnabled($taskPath, $taskName) {
    # Enumerate successfully before reading an unmatched name as absence, the way
    # Check-Status.ps1 does.
    $taskObject = Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -eq $taskPath -and $_.TaskName -eq $taskName
    }
    if ($null -eq $taskObject) { return $null }
    return ($taskObject.State -ne 'Disabled')
}
function Get-RegValue($path, $name) {
    # Only a missing key is an absent value; an access or read error propagates.
    $registryKey = try { Get-Item -LiteralPath $path -ErrorAction Stop } catch [System.Management.Automation.ItemNotFoundException] { $null }
    if ($null -eq $registryKey) { return $null }
    try {
        # Preserve expandable strings verbatim so restoration can return the original text.
        return $registryKey.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally { $registryKey.Dispose() }
}
# Every catalog entry of one backup section, read live; a value that is not
# set comes back as $null.
function Get-ProtectedRegistrySnapshot {
    param([string]$Section)
    $snapshot = @{}
    foreach ($entry in @(Get-ProtectedRegistryValues -IncludeUser)) {
        if ($entry.Section -ne $Section) { continue }
        $snapshot[$entry.Field] = Get-RegValue "$($entry.Hive):\$($entry.Path)" $entry.Name
    }
    return $snapshot
}

# Steps for Invoke-RegStep: one reg.exe write of the disabled value per catalog
# entry of the group.
function Get-ProtectedRegistryDisableSteps {
    param([string]$Group, $Backup)
    foreach ($entry in @(Get-ProtectedRegistryValues -IncludeUser)) {
        if ($entry.DisableGroup -ne $Group) { continue }
        if (-not (Test-RegistryEntryRecorded $Backup $entry)) { continue }
        $arguments = Get-ProtectedRegistryDisableArguments $entry
        @{ Label = $entry.Label; Cmd = { reg add $arguments.Path /v $arguments.Name /t $arguments.Type /d $arguments.Value /f }.GetNewClosure() }
    }
}

function Get-RegValueType($path, $name) {
    # Close() must be in finally to avoid leaking the handle on the exception path.
    $registryKey = $null
    try {
        $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            ($path -replace '^HKLM:\\', '').Replace('/', '\'))
        if ($null -eq $registryKey) { return $null }
        # GetValueKind throws for an absent name, so check the names first and let
        # every other error propagate instead of reading as "no type".
        if ($registryKey.GetValueNames() -notcontains $name) { return $null }
        return $registryKey.GetValueKind($name).ToString()
    } finally {
        if ($null -ne $registryKey) { $registryKey.Close() }
    }
}
function Get-EppGuid($subkeyPath) {
    $eppKey = $null
    try {
        $eppKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath)
        if ($null -eq $eppKey) { return $null }
        return $eppKey.GetValue('')
    } finally {
        if ($null -ne $eppKey) { $eppKey.Close() }
    }
}

# Declarative step runner for reg.exe operations.
# $Entries = array of @{ Label = '...'; Cmd = { reg add/delete ... } }
function Invoke-RegStep {
    param(
        [string]$Header,
        [array]$Entries
    )
    Write-StepStart $Header
    $stepResults = Invoke-RegStepOps $Entries
    if (Write-StepResult $stepResults 'Safe Mode will finish what was skipped.') {
        $script:HasErrors = $true
    }
}

# Preflight & operation functions
#
#  Read WinDefend Start value directly from registry -- same method as
#  Check-Status.ps1, no external process needed.
#  Start=4 means Disabled; anything else (or absent key) = treat as enabled.
#

function Show-UnfinishedOperationWarning {
    param([string]$OperationStatePath)
    $previousOperation = Get-OperationState $OperationStatePath
    if ($null -eq $previousOperation) { return }
    if ($previousOperation.Readable) {
        Write-Host "  [!] Unfinished $($previousOperation.Operation) operation found (stage: $($previousOperation.Stage), started $($previousOperation.StartedAt))." -ForegroundColor Yellow
    } else {
        Write-Host "  [!] An unfinished-operation marker exists but could not be read." -ForegroundColor Yellow
    }
    Write-Host "      Continuing will overwrite that marker with this run's progress." -ForegroundColor DarkGray
    Write-Host ""
}

# Returns 'Stop' (user declined -- caller exits 0), 'Confirmed' (user explicitly
# agreed, so the caller may skip the later generic confirmation) or
# 'NotApplicable' (Defender was not already disabled).
function Test-AlreadyDisabledConfirmation {
    param([switch]$Unattended)

    $wdStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -ErrorAction SilentlyContinue).Start
    if ($wdStart -ne 4) { return 'NotApplicable' }

    Write-Host "  [!] Defender is already disabled." -ForegroundColor Yellow
    if ($Unattended) {
        Write-Host "  [Unattended] Re-running the configuration." -ForegroundColor DarkGray
        Write-Host ""
        return 'Confirmed'
    }
    do {
        $userInput = (Read-Host "      Re-run the configuration? (Y/N)").Trim()
    } while ($userInput -ne 'y' -and $userInput -ne 'Y' -and $userInput -ne 'n' -and $userInput -ne 'N')
    Write-Host ""
    if ($userInput -eq 'n' -or $userInput -eq 'N') {
        Write-Host "  Exiting." -ForegroundColor DarkGray
        Write-Host ""
        return 'Stop'
    }
    return 'Confirmed'
}

# IsTamperProtected was added in Windows 10 1703; on 1607 LTSB the property
# is absent. PSObject.Properties[] guards the access so it does not silently
# return $null and skip the check on modern builds.
# Doesn't block: verified with it ON that Security Center,
# SmartScreen, the scheduled tasks, and the SecurityHealth Run key below
# all still get written. If anything does fail anyway, stage-safe.ps1
# reapplies Security Center/SmartScreen/SecurityHealth in Safe Mode
# regardless (Tamper Protection is inactive there).
function Show-TamperProtectionNotice {
    $mpStatus          = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $isTamperProtected = $null -ne $mpStatus -and
                         $null -ne $mpStatus.PSObject.Properties['IsTamperProtected'] -and
                         $mpStatus.IsTamperProtected
    if (-not $isTamperProtected) { return }
    Write-Host "  Tamper Protection is on; this is normal. Some settings will be applied in Safe Mode."
    Write-Host ""
}

# Returns 'Stop' (user declined -- caller exits 0), 'Refused' (an unattended run
# cannot agree for the user -- caller exits 2, "rejected before any change", so
# automation does not read it as a completed disable), 'Confirmed' (user
# explicitly agreed, so the caller may skip the later generic confirmation) or
# 'NotApplicable' (no third-party antivirus detected).
function Test-ThirdPartyAntivirusConfirmation {
    param([switch]$Unattended)

    # A failed query is not "no third-party antivirus": it is an unknown, and the
    # driver-conflict warning below applies to it just the same.
    $queryFailure = $null
    $thirdPartyAVList = $null
    try {
        $thirdPartyAVList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            Where-Object { $_.instanceGuid -notmatch '^\{D68DDC3A' }  # exclude Windows Defender itself
    } catch {
        $queryFailure = $_.Exception.Message
    }
    if ($null -eq $queryFailure -and -not $thirdPartyAVList) { return 'NotApplicable' }

    Write-Host ""
    if ($null -ne $queryFailure) {
        Write-WarningLine "Could not check for a third-party antivirus: $queryFailure"
    } else {
        $avNames = ($thirdPartyAVList | ForEach-Object { $_.displayName }) -join ', '
        Write-WarningLine "Third-party antivirus detected: $avNames"
    }
    Write-Host ""
    Write-Host "  Modifying Defender components alongside another AV may cause" -ForegroundColor DarkGray
    Write-Host "  driver conflicts or a BSOD on next boot." -ForegroundColor DarkGray
    Write-Host ""
    if ($Unattended) {
        Write-Host "  [Unattended] Declining by default. Exiting." -ForegroundColor DarkGray
        Write-Host ""
        return 'Refused'
    }
    do {
        $userInput = (Read-Host "      Continue anyway? (Y/N)").Trim()
    } while ($userInput -ne 'y' -and $userInput -ne 'Y' -and $userInput -ne 'n' -and $userInput -ne 'N')
    Write-Host ""
    if ($userInput -eq 'n' -or $userInput -eq 'N') {
        Write-Host "  Exiting." -ForegroundColor DarkGray
        Write-Host ""
        return 'Stop'
    }
    return 'Confirmed'
}

function Show-ChangeConfirmationPrompt {
    param([switch]$Unattended, [bool]$AlreadyConfirmed)
    if ($AlreadyConfirmed -or $Unattended) { return }
    Write-Host "  Save all open files.  Press any key to continue or close to cancel..." -ForegroundColor Yellow
    Invoke-ReadKey *> $null
    Write-Host ""
}

# [0/5] Backup
# Validates an existing backup, or collects and saves a new one.
# Throws on validation/creation failure -- the caller's try/catch exits 1.
function Invoke-BackupStep {
    param([string]$BackupPath, [switch]$Unattended)

    if (Test-Path $BackupPath) {
        try {
            $null = Read-BackupState $BackupPath
        } catch {
            Write-ErrorLine "Backup validation failed: $_"
            Write-Host "  Existing backup preserved. No further changes will be made." -ForegroundColor Yellow
            if (-not $Unattended) { Invoke-ReadKey *> $null }
            throw
        }
        Write-Host "  [0/5] Existing backup validated and preserved." -ForegroundColor DarkGray
        return
    }

    Write-StepStart '[0/5] Backing up current state'

    try {
        $controlSetTargets = Get-ControlSetTargets
        $backup = @{
            Timestamp = (Get-Date -Format 'o')
            Services  = @{
                WinDefend           = Get-ServiceStartByControlSet 'WinDefend'           $controlSetTargets
                WdFilter            = Get-ServiceStartByControlSet 'WdFilter'            $controlSetTargets
                MDCoreSvc           = Get-ServiceStartByControlSet 'MDCoreSvc'           $controlSetTargets
                WdBoot              = Get-ServiceStartByControlSet 'WdBoot'              $controlSetTargets
                WdNisSvc            = Get-ServiceStartByControlSet 'WdNisSvc'            $controlSetTargets
                WdNisDrv            = Get-ServiceStartByControlSet 'WdNisDrv'            $controlSetTargets
                Sense               = Get-ServiceStartByControlSet 'Sense'               $controlSetTargets
                webthreatdefsvc     = Get-ServiceStartByControlSet 'webthreatdefsvc'     $controlSetTargets
                webthreatdefusersvc = Get-ServiceStartByControlSet 'webthreatdefusersvc' $controlSetTargets
                wscsvc              = Get-ServiceStartByControlSet 'wscsvc'              $controlSetTargets
            }
            ScheduledTasks = @{
                CacheMaintenance    = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Cache Maintenance'
                Cleanup             = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Cleanup'
                ScheduledScan       = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Scheduled Scan'
                Verification        = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Verification'
                RecoverabilityToast = Get-TaskEnabled '\Microsoft\Windows\AccountHealth\'    'RecoverabilityToastTask'
            }
            SecurityCenter   = Get-ProtectedRegistrySnapshot 'SecurityCenter'
            SmartScreen      = Get-ProtectedRegistrySnapshot 'SmartScreen'
            Systray          = Get-ProtectedRegistrySnapshot 'Systray'
            AttachmentWarning = Get-ProtectedRegistrySnapshot 'AttachmentWarning'
            SecurityHealthAutorun = @{
                Value = Get-RegValue    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth'
                Type  = Get-RegValueType 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth'
            }
            EppContextMenu = @{
                Star      = Get-EppGuid 'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP'
                Drive     = Get-EppGuid 'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP'
                Directory = Get-EppGuid 'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP'
                DirBg     = Get-EppGuid 'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP'
                Folder    = Get-EppGuid 'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
            }
        }

        $backup.SecurityState = Get-SecurityState
        Write-BackupState $BackupPath $backup
    } catch {
        Write-StepFail
        Write-Host ""
        Write-ErrorLine "Failed to create a validated backup: $_"
        Write-Host "  No further changes will be made." -ForegroundColor Yellow
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw
    }
    Write-StepOk
    Write-Host "        Saved: defender-backup.json" -ForegroundColor DarkGray
}

# [Pre-reboot] Register Stage 2 in RunOnce for Safe Mode
#
#  Key name MUST start with '*' so Windows executes it in Safe Mode too.
#  Path is resolved here (Normal Mode) where $PSScriptRoot is reliable.
#  Stage 2 will clean this key up itself after it finishes.
#  Throws on failure -- the caller's try/catch exits 1.
#
function Register-SafeModeRunOnce {
    param([string]$OperationStatePath, [switch]$Unattended)

    Write-StepStart '[Pre-reboot] Registering Stage 2 in RunOnce'
    try {
        $launcherPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'launcher-safe.cmd'))
        if (-not (Test-Path $launcherPath)) {
            throw "Safe Mode launcher not found at: $launcherPath"
        }

        # RunOnce entries with the '*' prefix are launched by winlogon.exe via
        # CreateProcess (not ShellExecute), which parses cmd /c differently.
        # The safe form for paths with spaces is: cmd.exe /c ""path""
        # (double-double-quotes around the entire argument after /c).
        # An unattended run adds /Unattended after the path; cmd strips the first and
        # last quote, leaving "path" /Unattended. launcher-safe.cmd forwards it.
        $unattendedArgument = if ($Unattended) { ' /Unattended' } else { '' }
        $runOnceCmd = 'cmd.exe /c ""{0}"{1}"' -f $launcherPath, $unattendedArgument
        $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'

        Set-ItemProperty -Path $runOnceKey -Name '*LauncherSafe' -Value $runOnceCmd -Type String -Force
        Set-OperationState $OperationStatePath 'Disable' 'NormalDone'
        Write-StepOk
        Write-Host "        Registered: *LauncherSafe" -ForegroundColor DarkGray
        Write-Host "        -> $launcherPath" -ForegroundColor DarkGray
    } catch {
        Write-StepFail
        Write-Host ""
        Write-ErrorLine "Failed to register Stage 2 in RunOnce:"
        Write-Host "  $_" -ForegroundColor Yellow
        Write-LogLine "  $_"
        Write-Host ""
        Write-Host "  Aborting reboot. Steps already done in Normal Mode stay applied; run Restore to undo them." -ForegroundColor Yellow
        Write-Host ""
        # The Safe Mode step will not run now, so its pending entry must not stay.
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name '*LauncherSafe' -ErrorAction SilentlyContinue
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw
    }
}

# Reboots into Safe Mode. Throws on bcdedit failure (after cleaning up the
# RunOnce entry) -- the caller's try/catch exits 1.
function Enter-SafeMode {
    param([switch]$Unattended)

    Write-Host "  Next: Safe Mode finishes the remaining steps on its own, then reboots back to Windows." -ForegroundColor DarkGray
    Write-Host "  Press any key to reboot into Safe Mode..." -ForegroundColor Yellow
    if (-not $Unattended) { Invoke-ReadKey *> $null }

    try {
        $null = New-SafeModeBootEntry
        $bcdeditFailure = $null
    } catch {
        $bcdeditFailure = $_.Exception.Message
    }
    if ($null -ne $bcdeditFailure) {
        # Clean up RunOnce so the stale entry does not fire on the next normal boot
        $runOncePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        Remove-ItemProperty -Path $runOncePath -Name '*LauncherSafe' -ErrorAction SilentlyContinue
        $runOnceRemains = $null -ne (Get-ItemProperty -Path $runOncePath -Name '*LauncherSafe' -ErrorAction SilentlyContinue)

        Write-Host ""
        Write-ErrorLine "Failed to set Safe Mode via bcdedit."
        Write-Host "  $bcdeditFailure" -ForegroundColor Yellow
        Write-LogLine "  $bcdeditFailure"
        Write-Host ""
        if ($runOnceRemains) {
            Write-Host "  Reboot cancelled. The RunOnce entry could not be removed and may start the Safe Mode step at the next sign-in; /Restore cancels it." -ForegroundColor Yellow
        } else {
            Write-Host "  Reboot cancelled. RunOnce entry removed." -ForegroundColor Yellow
        }
        Write-Host "  Check bcdedit permissions (Secure Boot policy may block this)." -ForegroundColor DarkGray
        Write-Host ""
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw "bcdedit failed"
    }

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
}

# Entry point
Sep
Write-Host "  Step 1 of 2  --  Normal Mode" -ForegroundColor Cyan
Sep
Write-Host ""

$runLockPath = Get-RunLockPath
$runLock = Enter-RunLock $runLockPath
if ($null -eq $runLock) {
    Write-Host "  [!] Another Disable/Restore run is already in progress." -ForegroundColor Red
    Write-Host "      Exiting without making any change." -ForegroundColor DarkGray
    exit 1
}

Show-UnfinishedOperationWarning $operationStatePath

$alreadyConfirmed = $false

$alreadyDisabledResult = Test-AlreadyDisabledConfirmation -Unattended:$Unattended
if ($alreadyDisabledResult -eq 'Stop') { exit 0 }
if ($alreadyDisabledResult -eq 'Confirmed') { $alreadyConfirmed = $true }

Show-TamperProtectionNotice

$thirdPartyResult = Test-ThirdPartyAntivirusConfirmation -Unattended:$Unattended
if ($thirdPartyResult -eq 'Stop') { exit 0 }
if ($thirdPartyResult -eq 'Refused') { exit 2 }
if ($thirdPartyResult -eq 'Confirmed') { $alreadyConfirmed = $true }

Show-ChangeConfirmationPrompt -Unattended:$Unattended -AlreadyConfirmed:$alreadyConfirmed

try {
    try {
        Set-OperationState $operationStatePath 'Disable' 'NormalStarted'
    } catch {
        Write-ErrorLine "Could not record the operation marker: $_"
        Write-Host "  No changes were made." -ForegroundColor Yellow
        throw
    }

    $backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
    Invoke-BackupStep -BackupPath $backupPath -Unattended:$Unattended
    $currentBackup = Read-BackupState $backupPath
    $unrecordedEntries = @(Get-ProtectedRegistryValues -IncludeUser | Where-Object { -not (Test-RegistryEntryRecorded $currentBackup $_) })
    if ($unrecordedEntries.Count -gt 0) {
        Write-WarningLine 'The existing backup does not contain some newer settings; they will be left unchanged.'
        foreach ($entry in $unrecordedEntries) { Write-WarningLine "  Skipped: $($entry.Label)" }
    }

    # [1/5] Scheduled tasks
    Invoke-StepSafe '[1/5] Disabling scheduled tasks' @(
        @{ Label = 'Cache Maintenance';   Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Cache Maintenance' -ErrorAction Stop *> $null } },
        @{ Label = 'Cleanup';             Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Cleanup'           -ErrorAction Stop *> $null } },
        @{ Label = 'Scheduled Scan';      Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Scheduled Scan'   -ErrorAction Stop *> $null } },
        @{ Label = 'Verification';        Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Verification'     -ErrorAction Stop *> $null } },
        @{ Label = 'RecoverabilityToast'; Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AccountHealth\'    -TaskName 'RecoverabilityToastTask'            -ErrorAction Stop *> $null } }
    ) 'Safe Mode does not retry scheduled tasks: a task that failed stays enabled.'

    # [2/5] Security Center
    Invoke-RegStep '[2/5] Disabling Security Center' @(Get-ProtectedRegistryDisableSteps 'SecurityCenter' $currentBackup)

    # [3/5] SmartScreen
    Invoke-RegStep '[3/5] Disabling SmartScreen' @(Get-ProtectedRegistryDisableSteps 'SmartScreen' $currentBackup)

    # [4/5] Downloaded-file warning
    if ($null -eq $currentBackup.AttachmentWarning) {
        Write-Host "  [4/5] Disabling the downloaded-file warning... SKIPPED" -ForegroundColor DarkGray
        Write-Host "        The existing backup does not contain it; its original value is unknown." -ForegroundColor DarkGray
    } else {
        Invoke-RegStep '[4/5] Disabling the downloaded-file warning' @(Get-ProtectedRegistryDisableSteps 'AttachmentWarning' $currentBackup)
    }

    # [5/5] SecurityHealth autostart
    Invoke-StepSafe '[5/5] Removing SecurityHealth autorun' @(
        @{ Label = 'SecurityHealth (Run key)'; Action = { Remove-SecurityHealthAutorun }}
    ) 'Safe Mode will finish what was skipped.'

    Register-SafeModeRunOnce -OperationStatePath $operationStatePath -Unattended:$Unattended

    # Done
    Write-Host ""
    Sep

    if ($script:HasErrors) {
        Write-WarningLine 'Some components could not be processed in Normal Mode.'
        Write-Host "  Safe Mode will retry the registry and autorun steps; failed scheduled tasks are not retried." -ForegroundColor Yellow
        Write-LogLocation
    } else {
        Write-Host "  Done." -ForegroundColor Green
    }

    Sep
    Write-Host ""

    Enter-SafeMode -Unattended:$Unattended
} catch {
    exit 1
}
