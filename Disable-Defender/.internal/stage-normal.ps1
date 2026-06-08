<#
  stage-normal.ps1
  Run in NORMAL mode as Administrator (via Disable-Defender.cmd).
  The script will reboot into Safe Mode at the end.
#>

$ErrorActionPreference = 'Stop'

$script:HasErrors = $false

# ── Helpers ────────────────────────────────────────────────────────

function Sep { Write-Host ("  " + ("=" * 38)) -ForegroundColor DarkGray }

# Backup helpers -- read current state before any changes are made.
function Get-ServiceStart($svcName) {
    (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name Start -ErrorAction SilentlyContinue).Start
}
function Get-TaskEnabled($taskPath, $taskName) {
    $taskObject = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $taskObject) { return $null }
    return ($taskObject.State -ne 'Disabled')
}
function Get-RegValue($path, $name) {
    (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
}
function Get-RegValueType($path, $name) {
    # GetValueKind() throws when the value name is absent -- Close() must be in
    # finally to avoid leaking the handle on the exception path.
    $registryKey = $null
    try {
        $registryKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            ($path -replace '^HKLM:\\', '').Replace('/', '\'))
        if ($null -eq $registryKey) { return $null }
        return $registryKey.GetValueKind($name).ToString()
    } catch {
        return $null
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
    } catch {
        return $null
    } finally {
        if ($null -ne $eppKey) { $eppKey.Close() }
    }
}

# Invoke-ReadKey: wraps RawUI.ReadKey with a fallback for non-interactive hosts
# (RMM agents, WinRM, Task Scheduler, VS Code terminal).
# RawUI.ReadKey throws HostException in those environments; with $ErrorActionPreference='Stop'
# that is an unhandled crash. Returns the pressed character so Y/N prompts can inspect it.
# In the non-interactive fallback (Read-Host), returns the first char typed,
# or empty string -- callers treat non-Y as "No", which is the safe default.
function Invoke-ReadKey {
    try {
        $keyInfo = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        return $keyInfo.Character
    } catch {
        $response = Read-Host
        return if ($response.Length -gt 0) { $response[0] } else { '' }
    }
}

# Declarative step runner for PowerShell-cmdlet operations.
# $Ops = array of @{ Label = '...'; Action = { scriptblock } }
# Prints one "  OK" line on full success, or expands per-item on partial failure.
function Invoke-StepSafe {
    param(
        [string]$Header,
        [array]$Ops
    )

    Write-Host "  $Header..." -NoNewline -ForegroundColor Yellow

    $stepResults = @()
    foreach ($op in $Ops) {
        try {
            & $op.Action
            $stepResults += @{ Label = $op.Label; Ok = $true; Error = $null }
        } catch {
            $script:HasErrors = $true
            $stepResults += @{ Label = $op.Label; Ok = $false; Error = $_.ToString() }
        }
    }

    $failedResults = $stepResults | Where-Object { -not $_.Ok }

    if (-not $failedResults) {
        Write-Host "  OK" -ForegroundColor Green
    } else {
        Write-Host "  OK (partial  -  Safe Mode will finish)" -ForegroundColor Yellow
        foreach ($stepResult in $stepResults) {
            if ($stepResult.Ok) {
                Write-Host "    [+] $($stepResult.Label)" -ForegroundColor Green
            } else {
                Write-Host "    [~] $($stepResult.Label)" -ForegroundColor Yellow
                Write-Host "        $($stepResult.Error)" -ForegroundColor DarkGray
            }
        }
    }
}

# Declarative step runner for reg.exe operations.
# $Entries = array of @{ Label = '...'; Cmd = { reg add/delete ... } }
# Uses *> $null (not | Out-Null) -- piping through Out-Null resets $LASTEXITCODE to 0 in PS 5.1.
function Invoke-RegStep {
    param(
        [string]$Header,
        [array]$Entries
    )

    Write-Host "  $Header..." -NoNewline -ForegroundColor Yellow

    $failedLabels = @()
    foreach ($entry in $Entries) {
        & $entry.Cmd *> $null
        if ($LASTEXITCODE -ne 0) {
            $failedLabels += $entry.Label
            $script:HasErrors = $true
        }
    }

    if ($failedLabels.Count -eq 0) {
        Write-Host "  OK" -ForegroundColor Green
    } else {
        Write-Host "  OK (partial  -  Safe Mode will finish)" -ForegroundColor Yellow
        foreach ($entry in $Entries) {
            if ($failedLabels -contains $entry.Label) {
                Write-Host "    [~] $($entry.Label)" -ForegroundColor Yellow
            } else {
                Write-Host "    [+] $($entry.Label)" -ForegroundColor Green
            }
        }
    }
}

# ── Preflight: already-disabled check ─────────────────────────────
#
#  Read WinDefend Start value directly from registry -- same method as
#  Check-Status.ps1, no external process needed.
#  Start=4 means Disabled; anything else (or absent key) = treat as enabled.
#
Sep
Write-Host "  Step 1 of 2  --  Normal Mode" -ForegroundColor Cyan
Sep
Write-Host ""

$alreadyConfirmed = $false

$wdStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -ErrorAction SilentlyContinue).Start
if ($wdStart -eq 4) {
    Write-Host "  [!] Defender is already disabled." -ForegroundColor Yellow
    do {
        $userInput = (Read-Host "      Re-run the configuration? (Y/N)").Trim()
    } while ($userInput -ne 'y' -and $userInput -ne 'Y' -and $userInput -ne 'n' -and $userInput -ne 'N')
    Write-Host ""
    if ($userInput -eq 'n' -or $userInput -eq 'N') {
        Write-Host "  Exiting." -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }
    $alreadyConfirmed = $true
}

# ── Preflight: Tamper Protection check ────────────────────────────
# IsTamperProtected was added in Windows 10 1703; on 1607 LTSB the property
# is absent. PSObject.Properties[] guards the access so it does not silently
# return $null and skip the check on modern builds.
$mpStatus          = Get-MpComputerStatus -ErrorAction SilentlyContinue
$isTamperProtected = $null -ne $mpStatus -and
                     $null -ne $mpStatus.PSObject.Properties['IsTamperProtected'] -and
                     $mpStatus.IsTamperProtected
if ($isTamperProtected) {
    Write-Host "  [ERROR] Tamper Protection is ON." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Disable it first:" -ForegroundColor Yellow
    Write-Host "  Windows Security -> Virus & threat protection" -ForegroundColor DarkGray
    Write-Host "  -> Virus & threat protection settings" -ForegroundColor DarkGray
    Write-Host "  -> Tamper Protection -> Off" -ForegroundColor DarkGray
    Write-Host ""
    Invoke-ReadKey *> $null
    exit 1
}

# ── Preflight: Third-party antivirus check ────────────────────────
$thirdPartyAVList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Where-Object { $_.instanceGuid -notmatch '^\{D68DDC3A' }  # exclude Windows Defender itself

if ($thirdPartyAVList) {
    $avNames = ($thirdPartyAVList | ForEach-Object { $_.displayName }) -join ', '
    Write-Host ""
    Write-Host "  [WARNING] Third-party antivirus detected: $avNames" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Modifying Defender components alongside another AV may cause" -ForegroundColor DarkGray
    Write-Host "  driver conflicts or a BSOD on next boot." -ForegroundColor DarkGray
    Write-Host ""
    do {
        $userInput = (Read-Host "      Continue anyway? (Y/N)").Trim()
    } while ($userInput -ne 'y' -and $userInput -ne 'Y' -and $userInput -ne 'n' -and $userInput -ne 'N')
    Write-Host ""
    if ($userInput -eq 'n' -or $userInput -eq 'N') {
        Write-Host "  Exiting." -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }
    $alreadyConfirmed = $true
}

# ── Confirm before making any changes ─────────────────────────────
if (-not $alreadyConfirmed) {
    Write-Host "  Save all open files.  Press any key to continue or close to cancel..." -ForegroundColor Yellow
    Invoke-ReadKey *> $null
    Write-Host ""
}

# ── [0/4] Backup ──────────────────────────────────────────────────
$backupPath = Join-Path $PSScriptRoot 'defender-backup.json'

if (Test-Path $backupPath) {
    Write-Host "  [0/4] Backup already exists, skipping." -ForegroundColor DarkGray
} else {
    Write-Host "  [0/4] Backing up current state..." -ForegroundColor Yellow

    $backup = @{
        Timestamp = (Get-Date -Format 'o')
        Services  = @{
            WinDefend           = Get-ServiceStart 'WinDefend'
            WdFilter            = Get-ServiceStart 'WdFilter'
            WdBoot              = Get-ServiceStart 'WdBoot'
            WdNisSvc            = Get-ServiceStart 'WdNisSvc'
            WdNisDrv            = Get-ServiceStart 'WdNisDrv'
            Sense               = Get-ServiceStart 'Sense'
            webthreatdefsvc     = Get-ServiceStart 'webthreatdefsvc'
            webthreatdefusersvc = Get-ServiceStart 'webthreatdefusersvc'
            wscsvc              = Get-ServiceStart 'wscsvc'
        }
        ScheduledTasks = @{
            CacheMaintenance    = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Cache Maintenance'
            Cleanup             = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Cleanup'
            ScheduledScan       = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Scheduled Scan'
            Verification        = Get-TaskEnabled '\Microsoft\Windows\Windows Defender\' 'Windows Defender Verification'
            RecoverabilityToast = Get-TaskEnabled '\Microsoft\Windows\AccountHealth\'    'RecoverabilityToastTask'
        }
        SecurityCenter = @{
            AntiVirusDisableNotify = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify'
            AntiVirusOverride      = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride'
            ToastNotifyEnabled     = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled'
        }
        SmartScreen = @{
            PolicyValue   = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'         'EnableSmartScreen'
            ExplorerValue = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
            AppHostValue  = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost'  'EnableWebContentEvaluation'
        }
        Systray = @{
            HideSystray         = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray'
            DisableHealthCenter = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HealthCenter' 'DisableHealthCenter'
        }
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

    $backup | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $backupPath
    if (-not (Test-Path $backupPath)) {
        Write-Host "  FAIL" -ForegroundColor Red
        Write-Host ""
        Write-Host "  [ERROR] Failed to write backup file." -ForegroundColor Red
        Write-Host "  Check permissions on the script folder." -ForegroundColor Yellow
        Write-Host ""
        Invoke-ReadKey *> $null
        exit 1
    }
    Write-Host "        Saved: defender-backup.json" -ForegroundColor DarkGray
}

# ── [1/4] Scheduled tasks ─────────────────────────────────────────
Invoke-StepSafe '[1/4] Disabling scheduled tasks' @(
    @{ Label = 'Cache Maintenance';   Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Cache Maintenance' -ErrorAction Stop *> $null } },
    @{ Label = 'Cleanup';             Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Cleanup'           -ErrorAction Stop *> $null } },
    @{ Label = 'Scheduled Scan';      Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Scheduled Scan'   -ErrorAction Stop *> $null } },
    @{ Label = 'Verification';        Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -TaskName 'Windows Defender Verification'     -ErrorAction Stop *> $null } },
    @{ Label = 'RecoverabilityToast'; Action = { Disable-ScheduledTask -TaskPath '\Microsoft\Windows\AccountHealth\'    -TaskName 'RecoverabilityToastTask'            -ErrorAction Stop *> $null } }
)

# ── [2/4] Security Center ─────────────────────────────────────────
Invoke-RegStep '[2/4] Disabling Security Center' @(
    @{ Label = 'AntiVirusDisableNotify'; Cmd = { reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f } },
    @{ Label = 'AntiVirusOverride';      Cmd = { reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusOverride      /t REG_DWORD /d 1 /f } },
    @{ Label = 'Toast notifications';    Cmd = { reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f } },
    @{ Label = 'HideSystray';            Cmd = { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray        /t REG_DWORD /d 1 /f } },
    @{ Label = 'DisableHealthCenter';    Cmd = { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HealthCenter"                    /v DisableHealthCenter /t REG_DWORD /d 1 /f } }
)

# ── [3/4] SmartScreen ─────────────────────────────────────────────
Invoke-RegStep '[3/4] Disabling SmartScreen' @(
    @{ Label = 'Policy (EnableSmartScreen)';     Cmd = { reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"             /v EnableSmartScreen          /t REG_DWORD /d 0   /f } },
    @{ Label = 'Explorer (SmartScreenEnabled)';  Cmd = { reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"     /v SmartScreenEnabled         /t REG_SZ    /d Off /f } },
    @{ Label = 'AppHost (WebContentEvaluation)'; Cmd = { reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost"      /v EnableWebContentEvaluation /t REG_DWORD /d 0   /f } }
)

# ── [4/4] SecurityHealth autostart ────────────────────────────────
Invoke-StepSafe '[4/4] Removing SecurityHealth autorun' @(
    @{ Label = 'SecurityHealth (Run key)'; Action = {
        $runKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $isPresent  = $null -ne (Get-ItemProperty -Path $runKeyPath -Name SecurityHealth -ErrorAction SilentlyContinue).SecurityHealth
        if ($isPresent) {
            Remove-ItemProperty -Path $runKeyPath -Name 'SecurityHealth' -Force -ErrorAction Stop
        }
        # Already absent -- not an error, silently OK
    }}
)

# ── [Pre-reboot] Register Stage 2 in RunOnce for Safe Mode ────────
#
#  Key name MUST start with '*' so Windows executes it in Safe Mode too.
#  Path is resolved here (Normal Mode) where $PSScriptRoot is reliable.
#  Stage 2 will clean this key up itself after it finishes.
#
Write-Host "  [Pre-reboot] Registering Stage 2 in RunOnce..." -NoNewline -ForegroundColor Yellow
try {
    $launcherPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'launcher-safe.cmd'))
    if (-not (Test-Path $launcherPath)) {
        throw "Safe Mode launcher not found at: $launcherPath"
    }

    # RunOnce entries with the '*' prefix are launched by winlogon.exe via
    # CreateProcess (not ShellExecute), which parses cmd /c differently.
    # The safe form for paths with spaces is: cmd.exe /c ""path""
    # (double-double-quotes around the entire argument after /c).
    $runOnceCmd = 'cmd.exe /c ""{0}""' -f $launcherPath
    $runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'

    Set-ItemProperty -Path $runOnceKey -Name '*LauncherSafe' -Value $runOnceCmd -Type String -Force
    Write-Host "  OK" -ForegroundColor Green
    Write-Host "        Registered: *LauncherSafe" -ForegroundColor DarkGray
    Write-Host "        -> $launcherPath" -ForegroundColor DarkGray
} catch {
    Write-Host "  FAIL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [ERROR] Failed to register Stage 2 in RunOnce:" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Aborting reboot. No changes will take effect until Safe Mode step." -ForegroundColor Yellow
    Write-Host ""
    Invoke-ReadKey *> $null
    exit 1
}

# ── Done ──────────────────────────────────────────────────────────
Write-Host ""
Sep

if ($script:HasErrors) {
    Write-Host "  [WARNING] Some components could not be processed in Normal Mode." -ForegroundColor Yellow
    Write-Host "  Safe Mode will finish what was skipped." -ForegroundColor Yellow
} else {
    Write-Host "  Done." -ForegroundColor Green
}

Sep
Write-Host ""
Write-Host "  Press any key to reboot into Safe Mode..." -ForegroundColor Yellow
Invoke-ReadKey *> $null

$bcdeditOutput = bcdedit /set "{current}" safeboot minimal 2>&1
if ($LASTEXITCODE -ne 0) {
    # Clean up RunOnce so the stale entry does not fire on the next normal boot
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' `
        -Name '*LauncherSafe' -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  [ERROR] Failed to set Safe Mode via bcdedit." -ForegroundColor Red
    Write-Host "  $bcdeditOutput" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Reboot cancelled. RunOnce entry removed." -ForegroundColor Yellow
    Write-Host "  Check bcdedit permissions (Secure Boot policy may block this)." -ForegroundColor DarkGray
    Write-Host ""
    Invoke-ReadKey *> $null
    exit 1
}

shutdown /r /t 0
if ($LASTEXITCODE -ne 0) {
    # shutdown.exe absent (Embedded / LTSB / Server Core) -- fallback to WMI cmdlet
    Restart-Computer -Force
}
