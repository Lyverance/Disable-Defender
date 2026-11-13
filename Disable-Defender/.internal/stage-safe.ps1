<#
  stage-safe.ps1
  Run in SAFE MODE via launcher-safe.cmd.
#>

param([switch]$Unattended)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'operation-state.ps1')
. (Join-Path $PSScriptRoot 'console-ui.ps1')
. (Join-Path $PSScriptRoot 'step-runner.ps1')
. (Join-Path $PSScriptRoot 'backup-state.ps1')
. (Join-Path $PSScriptRoot 'autorun-state.ps1')
. (Join-Path $PSScriptRoot 'safe-mode-entry.ps1')

$script:HasErrors = $false
$operationStatePath = Join-Path $PSScriptRoot 'operation-state.json'
Set-LogFilePath (Join-Path $PSScriptRoot 'defender-log.txt')

# Helpers

# takeown helper -- suppresses localized output, throws on failure.
function Invoke-TakeOwn {
    param([string]$Path)
    & takeown /f "$Path" /a *> $null
    if ($LASTEXITCODE -ne 0) { throw "takeown failed (exit $LASTEXITCODE)" }
}

# icacls helper -- suppresses localized output, throws on failure.
function Invoke-Icacls {
    param([string[]]$IcaclsArgs)
    & icacls @IcaclsArgs *> $null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed (exit $LASTEXITCODE)" }
}

# Preflight & step functions
# Throws on failure -- the caller's try/catch exits 1.
function Test-SafeModePreflight {
    $safeBootOption = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option' -ErrorAction SilentlyContinue
    if ($safeBootOption) { return }
    Write-Host ""
    Write-ErrorLine 'This script must run in Safe Mode.'
    Write-Host "  Run launcher-safe.cmd after rebooting into Safe Mode." -ForegroundColor Yellow
    Write-Host ""
    if (-not $Unattended) { Invoke-ReadKey *> $null }
    throw "Not running in Safe Mode"
}

# launcher-safe.cmd already cleared the Safe Mode flag, so a failed step leaves
# only this session in Safe Mode and the next boot is normal. Say why on screen
# and in the log, and when no one is there to press a key return to normal mode
# on our own instead of leaving the machine sitting in Safe Mode.
function Exit-AfterSafeModeFailure {
    param($ErrorRecord)
    Write-Host ""
    Write-ErrorLine "Step 2 stopped before it finished: $($ErrorRecord.Exception.Message)"
    Write-Host "  Defender is not fully disabled. Restart Windows normally, then run" -ForegroundColor Yellow
    Write-Host "  Defender.cmd /Status to see what was applied, or /Restore to roll back." -ForegroundColor Yellow
    Write-LogLocation
    $inSafeMode = $null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option' -ErrorAction SilentlyContinue)
    if ($Unattended -and $inSafeMode) {
        Write-Host "  Rebooting into normal mode in 5 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $restartStarted = $false
        try {
            shutdown /r /t 0
            $restartStarted = ($LASTEXITCODE -eq 0)
        } catch {
            $restartStarted = $false
        }
        if (-not $restartStarted) { Restart-Computer -Force }
    }
    exit 1
}

# [1/6] Take ownership
# Throws on failure -- the caller's try/catch exits 1.
function Invoke-TakeOwnershipStep {
    # Shell out before starting the line -- see the matching note in
    # restore-from-backup.ps1's Invoke-TakeOwnershipStep. Write-StepPending logs
    # the attempt before that call for the same reason.
    Write-StepPending '[1/6] Taking registry ownership'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action take *> $null
    Write-StepPrint '[1/6] Taking registry ownership'
    if ($LASTEXITCODE -ne 0) {
        Write-StepFail
        Write-Host ""
        Write-ErrorLine 'Failed to take ownership.'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore *> $null
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Could not restore registry security after the failed operation.' }
        Write-Host "  Make sure you are in Safe Mode and running as Administrator." -ForegroundColor Red
        Write-Host ""
        Write-Host "  If Defender is still active, run Defender.cmd /Restore" -ForegroundColor Yellow
        Write-Host "  to roll back to the previous state." -ForegroundColor Yellow
        Write-Host ""
        if (-not $Unattended) { Invoke-ReadKey *> $null }
        throw "Failed to take registry ownership"
    }
    Write-StepOk
}

# [2/6] Security Center & SmartScreen (final pass)
#
#  Tamper Protection is inactive in Safe Mode -- these always succeed here
#  even if stage-normal was PARTIAL on some of them.
#  wscsvc (Windows Security Center) is left running -- the
#  DisableNotifications/DisableEnhancedNotifications pair below (and
#  HideSystray/DisableHealthCenter, both already Policies-branch values) hide
#  the notifications it would otherwise show, without killing the service.
#  Using reg.exe directly -- avoids any scope/wrapper issues.
#
function Invoke-SecurityCenterFinalizeStep {
    param($Backup, [switch]$IncludeUser)
    Write-StepStart '[2/6] Finalizing Security Center & SmartScreen'

    $step2Entries = @(Get-ProtectedRegistryValues -IncludeUser:$IncludeUser | Where-Object { $_.FinalizeInSafeMode -and (Test-RegistryEntryRecorded $Backup $_) } | ForEach-Object { Get-ProtectedRegistryDisableArguments $_ })

    $stepResults = foreach ($entry in $step2Entries) {
        # *> $null preserves $LASTEXITCODE; | Out-Null resets it to 0 in PS 5.1.
        reg add "$($entry.Path)" /v "$($entry.Name)" /t "$($entry.Type)" /d "$($entry.Value)" /f *> $null
        [pscustomobject]@{ Label = $entry.Name; Ok = ($LASTEXITCODE -eq 0); Error = "reg.exe exit $LASTEXITCODE" }
    }

    if (Write-StepResult $stepResults) {
        $script:HasErrors = $true
    }
}

# [4/6] Disable services
function Invoke-DisableServicesStep {
    Write-StepStart '[4/6] Disabling Defender services'

    # Keep wscsvc running to preserve monitoring of firewall, updates, UAC and other antivirus software.
    $serviceNames = @(
        'WinDefend'
        'WdFilter'
        'MDCoreSvc'
        'WdBoot'              # ELAM boot-start driver (Start=0 normally); disabling prevents Safe Mode re-arm
        'WdNisSvc'
        'WdNisDrv'
        'Sense'
        'webthreatdefsvc'
        'webthreatdefusersvc'
    )

    # Find all concrete ControlSets (ControlSet001, ControlSet002, etc.)
    # CurrentControlSet is just an alias -- write to the real ones directly.
    # Each probe handle is closed immediately after the existence check;
    # open raw handles to SYSTEM\ControlSet* are a known EDR detection pattern.
    $controlSets = @()
    foreach ($controlSetIndex in 1..3) {
        $csName          = 'ControlSet{0:D3}' -f $controlSetIndex
        $controlSetProbe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName")
        if ($null -ne $controlSetProbe) {
            $controlSetProbe.Close()
            $controlSets += $csName
        }
    }

    $svcFailedEntries = @()
    foreach ($csName in $controlSets) {
        foreach ($svcName in $serviceNames) {
            # OpenSubKey($true) returns $null for both absent key and Access Denied --
            # check read-only first to distinguish the two cases.
            $registryKeyReadOnly = $null
            $registryKeyWritable = $null
            try {
                $registryKeyReadOnly = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "SYSTEM\$csName\Services\$svcName", $false)
                if ($null -eq $registryKeyReadOnly) { continue }  # key absent -- not an error

                $registryKeyWritable = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "SYSTEM\$csName\Services\$svcName", $true)
                if ($null -eq $registryKeyWritable) {
                    throw "Access denied (key exists but write rejected)"
                }
                $registryKeyWritable.SetValue('Start', 4, [Microsoft.Win32.RegistryValueKind]::DWord)
            } catch {
                $svcFailedEntries += "$svcName ($csName): $_"
                $script:HasErrors = $true
            } finally {
                if ($null -ne $registryKeyWritable) { $registryKeyWritable.Close() }
                if ($null -ne $registryKeyReadOnly)  { $registryKeyReadOnly.Close()  }
            }
        }
    }

    if ($svcFailedEntries.Count -eq 0) {
        Write-StepOk
    } else {
        Write-StepWarn 'PARTIAL'
        foreach ($failedEntry in $svcFailedEntries) {
            Write-WarningLine $failedEntry
        }
        Write-Host ""
    }
}

# [6/6] Restore ownership
function Invoke-RestoreOwnershipStep {
    # Shell out before starting the line -- see the matching note in
    # restore-from-backup.ps1's Invoke-TakeOwnershipStep. Write-StepPending logs
    # the attempt before that call for the same reason.
    Write-StepPending '[6/6] Restoring registry security'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore *> $null
    Write-StepPrint '[6/6] Restoring registry security'
    if ($LASTEXITCODE -ne 0) {
        Write-StepWarn
        Write-Host ""
        Write-WarningLine 'Failed to restore registry security.'
        Write-Host "  Registry owner or permissions may differ from the saved state." -ForegroundColor DarkGray
        Write-Host "  Retry restoration to recover the saved registry security." -ForegroundColor DarkGray
        Write-Host ""
        $script:HasErrors = $true
    } else {
        Write-StepOk
    }
}

# Entry point
try {
    Test-SafeModePreflight

    # The one-shot Safe Mode entry has done its job once this boot is Safe Mode;
    # a failed removal only leaves an unused hidden entry that the next Disable
    # or Restore removes.
    try {
        Remove-SafeModeBootEntry
    } catch {
        Write-WarningLine "Could not remove the temporary Safe Mode boot entry: $($_.Exception.Message)"
    }

    Sep
    Write-Host "  Step 2 of 2  --  Safe Mode" -ForegroundColor Cyan
    Sep
    Write-Host ""

    Set-OperationState $operationStatePath 'Disable' 'SafeModeStarted'

    # Whoever signs in first in Safe Mode runs this stage, which need not be the
    # account that started Disable: system settings still apply from the backup,
    # the signed-in account's own settings only when the backup is theirs.
    $backup = Read-BackupState (Join-Path $PSScriptRoot 'defender-backup.json') -AllowOtherUser
    $backupIsOwnedByThisUser = $null -eq $backup.Identity -or $backup.Identity.UserSid -eq (Get-BackupIdentity).UserSid
    if (-not $backupIsOwnedByThisUser) {
        Write-WarningLine 'Backup belongs to another account on this Windows installation.'
        Write-Host "  System settings are applied; this account's settings are left unchanged." -ForegroundColor Yellow
    }
    Invoke-TakeOwnershipStep
    Invoke-SecurityCenterFinalizeStep $backup -IncludeUser:$backupIsOwnedByThisUser

    # [3/6] EPP context menu
    #
    #  parentKey.Close() is in finally -- a throw from DeleteSubKeyTree
    #  would otherwise leave the handle open.
    #
    Invoke-StepSafe '[3/6] Removing EPP context menu' @(
        @{ Label = 'Classes\*\EPP';                    Action = {
            $parentKeyPath = 'SOFTWARE\Classes\*\shellex\ContextMenuHandlers'
            $parentKey     = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentKeyPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree('EPP', $false) }
            } finally {
                if ($null -ne $parentKey) { $parentKey.Close() }
            }
        }},
        @{ Label = 'Classes\Drive\EPP';                Action = {
            $parentKeyPath = 'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers'
            $parentKey     = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentKeyPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree('EPP', $false) }
            } finally {
                if ($null -ne $parentKey) { $parentKey.Close() }
            }
        }},
        @{ Label = 'Classes\Directory\EPP';            Action = {
            $parentKeyPath = 'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'
            $parentKey     = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentKeyPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree('EPP', $false) }
            } finally {
                if ($null -ne $parentKey) { $parentKey.Close() }
            }
        }},
        @{ Label = 'Classes\Directory\Background\EPP'; Action = {
            $parentKeyPath = 'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers'
            $parentKey     = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentKeyPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree('EPP', $false) }
            } finally {
                if ($null -ne $parentKey) { $parentKey.Close() }
            }
        }},
        @{ Label = 'Classes\Folder\EPP';               Action = {
            $parentKeyPath = 'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers'
            $parentKey     = $null
            try {
                $parentKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentKeyPath, $true)
                if ($null -ne $parentKey) { $parentKey.DeleteSubKeyTree('EPP', $false) }
            } finally {
                if ($null -ne $parentKey) { $parentKey.Close() }
            }
        }}
    )

    Invoke-DisableServicesStep

    # [5/6] Block smartscreen.exe & remove SecurityHealth autorun
    #
    #  SecurityHealth Run key is removed here because SecurityHealthSystray.exe
    #  restores it on every normal boot -- in Safe Mode it cannot do that.
    #  Test-Path guard before takeown -- smartscreen.exe is absent on Windows
    #  Server Core, where takeown on a missing path returns non-zero.
    #
    Invoke-StepSafe '[5/6] Blocking smartscreen.exe & removing SecurityHealth autorun' @(
        @{ Label = 'takeown smartscreen.exe';  Action = {
            $smartscreenPath = "$env:SystemRoot\System32\smartscreen.exe"
            if (Test-Path $smartscreenPath) {
                Invoke-TakeOwn $smartscreenPath
            }
            # Absent on Server Core -- not an error
        }},
        @{ Label = 'icacls deny execute';      Action = {
            $smartscreenPath = "$env:SystemRoot\System32\smartscreen.exe"
            if (Test-Path $smartscreenPath) {
                Invoke-Icacls @($smartscreenPath, '/deny', '*S-1-5-32-545:(X)')
            }
        }},
        @{ Label = 'SecurityHealth Run key';   Action = { Remove-SecurityHealthAutorun }}
    )

    Invoke-RestoreOwnershipStep

    # [Cleanup] Remove RunOnce key
    $runOnceKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Remove-ItemProperty -Path $runOnceKeyPath -Name '*LauncherSafe' -ErrorAction SilentlyContinue

    # Reaching this point means the pipeline ran to its last stage -- clear the
    # marker even if some steps above were partial; "unfinished" means it never
    # got here, not that a step inside it failed.
    Clear-OperationState $operationStatePath

    # Done
    Write-Host ""
    Sep
    if ($script:HasErrors) {
        Write-Host "  Finished with errors: Defender may not be fully disabled." -ForegroundColor Yellow
        Write-Host "  Some steps were partial  -  see above for details." -ForegroundColor Yellow
        Write-LogLocation
    } else {
        Write-Host "  Done. Defender is disabled." -ForegroundColor Green
    }
    Sep
    Write-Host ""
    Write-Host "  Next: reboots into Windows normally. No further action needed." -ForegroundColor DarkGray

    # Remove the temporary Safe Mode boot entry (safety net)
    #
    #  Already removed at the start of this stage; this call covers a stage
    #  started in a way that skipped that point. Normal Windows never had the
    #  flag, so no reboot can land back in Safe Mode.
    #
    try {
        Remove-SafeModeBootEntry
    } catch {
        Write-WarningLine "Could not remove the temporary Safe Mode boot entry: $($_.Exception.Message)"
    }

    # Reboot strategy for Safe Mode (R-23 revised):
    #   Restart-Computer -Force throws AggregateException in Safe Mode because
    #   the WMI/CIM stack it relies on is not fully initialized there.
    #   shutdown.exe is the reliable choice in Safe Mode.
    #   Fallback to Restart-Computer covers Embedded/LTSB/Server Core images
    #   where shutdown.exe may be absent.
    Write-Host "  Rebooting in 5 seconds..." -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 5
    # A missing shutdown.exe throws under 'Stop' instead of setting $LASTEXITCODE,
    # so the lookup failure is caught here to reach the cmdlet fallback.
    $restartStarted = $false
    try {
        shutdown /r /t 0
        $restartStarted = ($LASTEXITCODE -eq 0)
    } catch {
        $restartStarted = $false
    }
    if (-not $restartStarted) { Restart-Computer -Force }
} catch {
    Exit-AfterSafeModeFailure $_
}
