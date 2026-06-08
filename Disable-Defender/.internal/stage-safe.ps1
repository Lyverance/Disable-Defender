<#
  stage-safe.ps1
  Run in SAFE MODE via launcher-safe.cmd.
#>

$ErrorActionPreference = 'Stop'

$script:HasErrors = $false

# ── Helpers ────────────────────────────────────────────────────────

function Sep { Write-Host ("  " + ("=" * 38)) -ForegroundColor DarkGray }

# Declarative step runner -- same pattern as stage-normal.
# $Ops = array of @{ Label = '...'; Action = { scriptblock } }
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
        Write-Host "  PARTIAL" -ForegroundColor Yellow
        foreach ($stepResult in $stepResults) {
            if ($stepResult.Ok) {
                Write-Host "    [+] $($stepResult.Label)" -ForegroundColor Green
            } else {
                Write-Host "    [~] $($stepResult.Label)" -ForegroundColor Yellow
                Write-Host "        $($stepResult.Error)" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
}

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

# ── Preflight: must run in Safe Mode ──────────────────────────────
$safeBootOption = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option' -ErrorAction SilentlyContinue
if (-not $safeBootOption) {
    Write-Host ""
    Write-Host "  [ERROR] This script must run in Safe Mode." -ForegroundColor Red
    Write-Host "  Run launcher-safe.cmd after rebooting into Safe Mode." -ForegroundColor Yellow
    Write-Host ""
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Read-Host | Out-Null }
    exit 1
}

Sep
Write-Host "  Step 2 of 2  --  Safe Mode" -ForegroundColor Cyan
Sep
Write-Host ""

# ── [1/6] Take ownership ──────────────────────────────────────────
Write-Host "  [1/6] Taking registry ownership..." -NoNewline -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action take *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAIL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  [ERROR] Failed to take ownership." -ForegroundColor Red
    Write-Host "  Make sure you are in Safe Mode and running as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "  If Defender is still active, run Restore-Defender.cmd" -ForegroundColor Yellow
    Write-Host "  to roll back to the previous state." -ForegroundColor Yellow
    Write-Host ""
    try { $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch { Read-Host | Out-Null }
    exit 1
}
Write-Host "  OK" -ForegroundColor Green

# ── [2/6] Security Center & SmartScreen (final pass) ──────────────
#
#  Tamper Protection is inactive in Safe Mode -- these always succeed here
#  even if stage-normal was PARTIAL on some of them.
#  wscsvc (Windows Security Center) is disabled as a service in [4/6],
#  so HideSystray / DisableHealthCenter are no longer needed here --
#  a dead service cannot show notifications regardless of those registry flags.
#  Using reg.exe directly -- avoids any scope/wrapper issues.
#
Write-Host "  [2/6] Finalizing Security Center & SmartScreen..." -NoNewline -ForegroundColor Yellow

$step2Entries = @(
    @{ Path = 'HKLM\SOFTWARE\Microsoft\Security Center';                                                                                         Name = 'AntiVirusDisableNotify';      Type = 'REG_DWORD'; Value = '1'   }
    @{ Path = 'HKLM\SOFTWARE\Microsoft\Security Center';                                                                                         Name = 'AntiVirusOverride';           Type = 'REG_DWORD'; Value = '1'   }
    @{ Path = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance';                Name = 'Enabled';                     Type = 'REG_DWORD'; Value = '0'   }
    @{ Path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System';                                                                                 Name = 'EnableSmartScreen';           Type = 'REG_DWORD'; Value = '0'   }
    @{ Path = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer';                                                                         Name = 'SmartScreenEnabled';          Type = 'REG_SZ';    Value = 'Off' }
    @{ Path = 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost';                                                                          Name = 'EnableWebContentEvaluation';  Type = 'REG_DWORD'; Value = '0'   }
)

$step2FailedNames = @()
foreach ($entry in $step2Entries) {
    # *> $null preserves $LASTEXITCODE; | Out-Null resets it to 0 in PS 5.1.
    reg add "$($entry.Path)" /v "$($entry.Name)" /t "$($entry.Type)" /d "$($entry.Value)" /f *> $null
    if ($LASTEXITCODE -ne 0) {
        $step2FailedNames += $entry.Name
        $script:HasErrors = $true
    }
}

if ($step2FailedNames.Count -eq 0) {
    Write-Host "  OK" -ForegroundColor Green
} else {
    Write-Host "  PARTIAL" -ForegroundColor Yellow
    foreach ($entry in $step2Entries) {
        if ($step2FailedNames -contains $entry.Name) {
            Write-Host "    [~] $($entry.Name)" -ForegroundColor Yellow
        } else {
            Write-Host "    [+] $($entry.Name)" -ForegroundColor Green
        }
    }
    Write-Host ""
}

# ── [3/6] EPP context menu ────────────────────────────────────────
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

# ── [4/6] Disable services ────────────────────────────────────────
Write-Host "  [4/6] Disabling Defender services..." -NoNewline -ForegroundColor Yellow

# wscsvc (Windows Security Center) is included here.
# It is a pure notification aggregator with no effect on hardware or laptop sensors.
# Disabling it is the only reliable way to suppress "Defender is off" toast notifications.
$serviceNames = @(
    'WinDefend'
    'WdFilter'
    'WdBoot'              # ELAM boot-start driver (Start=0 normally); disabling prevents Safe Mode re-arm
    'WdNisSvc'
    'WdNisDrv'
    'Sense'
    'webthreatdefsvc'
    'webthreatdefusersvc'
    'wscsvc'              # Windows Security Center -- stops notification toasts
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
    Write-Host "  OK" -ForegroundColor Green
} else {
    Write-Host "  PARTIAL" -ForegroundColor Yellow
    $svcFailedEntries | ForEach-Object { Write-Host "    [~] $_" -ForegroundColor Yellow }
    Write-Host ""
}

# ── [5/6] Block smartscreen.exe & remove SecurityHealth autorun ───
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
    @{ Label = 'SecurityHealth Run key';   Action = {
        # Use native PS API -- reg.exe returns non-zero and writes stderr
        # when the value is absent, which Invoke-StepSafe catches as PARTIAL
        # even though absence is not an error.
        $runKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        $isPresent  = $null -ne (Get-ItemProperty -Path $runKeyPath -Name SecurityHealth -ErrorAction SilentlyContinue).SecurityHealth
        if ($isPresent) {
            Remove-ItemProperty -Path $runKeyPath -Name SecurityHealth -Force -ErrorAction Stop
        }
        # Already absent -- that is fine, not an error
    }}
)

# ── [6/6] Restore ownership ───────────────────────────────────────
Write-Host "  [6/6] Returning ownership to SYSTEM..." -NoNewline -ForegroundColor Yellow
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\registry-privileges.ps1" -Action restore *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [WARNING] Failed to return registry ownership to SYSTEM." -ForegroundColor Yellow
    Write-Host "  Defender is disabled, but registry keys are still owned by Administrators." -ForegroundColor DarkGray
    Write-Host "  This is cosmetic -- Defender will not re-enable." -ForegroundColor DarkGray
    Write-Host ""
    $script:HasErrors = $true
} else {
    Write-Host "  OK" -ForegroundColor Green
}

# ── [Cleanup] Remove RunOnce key ──────────────────────────────────
$runOnceKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
Remove-ItemProperty -Path $runOnceKeyPath -Name '*LauncherSafe' -ErrorAction SilentlyContinue

# ── Done ──────────────────────────────────────────────────────────
Write-Host ""
Sep
Write-Host "  Done. Defender is disabled." -ForegroundColor Green
if ($script:HasErrors) {
    Write-Host "  Some steps were partial  -  see above for details." -ForegroundColor Yellow
}
Sep
Write-Host ""

# ── Clear Safe Mode flag (safety net) ─────────────────────────────
#
#  launcher-safe.cmd already ran bcdedit at startup, so the flag is
#  normally gone by the time we reach here.  This second call is a
#  no-op safety net in case stage-safe.ps1 was launched directly
#  (not via the launcher).  bcdedit returns non-zero when the element
#  is already absent -- that is expected, so we suppress the exit code.
#
bcdedit /deletevalue "{current}" safeboot *> $null

# Reboot strategy for Safe Mode (R-23 revised):
#   Restart-Computer -Force throws AggregateException in Safe Mode because
#   the WMI/CIM stack it relies on is not fully initialized there.
#   shutdown.exe is the reliable choice in Safe Mode.
#   Fallback to Restart-Computer covers Embedded/LTSB/Server Core images
#   where shutdown.exe may be absent.
Write-Host "  Rebooting in 5 seconds..." -ForegroundColor Yellow
Write-Host ""
Start-Sleep -Seconds 5
shutdown /r /t 0
if ($LASTEXITCODE -ne 0) {
    # shutdown.exe absent (Embedded / LTSB / Server Core) -- try WMI cmdlet
    Restart-Computer -Force
}
