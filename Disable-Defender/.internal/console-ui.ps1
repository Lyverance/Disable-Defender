# console-ui.ps1 -- shared console presentation helpers used by multiple entry points.
#
# Color by meaning, consistently across stage-normal/stage-safe/restore-from-backup/
# Check-Status: normal progress uses the console's default foreground (no
# -ForegroundColor at all) -- Green is reserved for success, Yellow for warning
# and partial results, Red for error. Write-Step* below is the one place that
# rule lives; callers should not pick colors for step headers themselves.

. (Join-Path $PSScriptRoot 'log-file.ps1')

function Sep { Write-Host ("  " + ("=" * 38)) -ForegroundColor DarkGray }

# Starts a step line without committing to its outcome yet: "  [1/4] Header... ".
# Remembered so Write-StepOk/Fail/Warn can log a complete "Header... OUTCOME" line --
# the console builds that line with -NoNewline, but the log file is line-oriented.
$script:CurrentStepHeader = $null

function Write-StepStart {
    param([string]$Header)
    Write-StepPending $Header
    Write-StepPrint $Header
}

# Logs that a step is about to run, without printing the console line yet --
# pair with Write-StepPrint when a risky call (shelling out to another process)
# has to happen before the console line can be printed (see restore-from-backup.ps1
# and stage-safe.ps1's ownership steps). A crash or killed process mid-step must
# still leave a trace of which step was running, not just the last one that
# finished, so this has to log before that call, not after.
function Write-StepPending {
    param([string]$Header)
    $script:CurrentStepHeader = $Header
    Write-LogLine "  $Header..."
}

# Prints the console line without re-logging it -- use after Write-StepPending
# once the risky call it was guarding has returned.
function Write-StepPrint {
    param([string]$Header)
    Write-Host "  $Header... " -NoNewline
}

function Write-StepOk {
    Write-Host "OK" -ForegroundColor Green
    Write-LogLine "  $script:CurrentStepHeader... OK"
}

function Write-StepFail {
    Write-Host "FAIL" -ForegroundColor Red
    Write-LogLine "  $script:CurrentStepHeader... FAIL"
}

function Write-StepWarn {
    param([string]$Text = "WARNING")
    Write-Host $Text -ForegroundColor Yellow
    Write-LogLine "  $script:CurrentStepHeader... $Text"
}

# The failure/warning reason callers print right after Write-StepFail/Write-StepWarn
# (e.g. "[ERROR] Failed to take ownership. Run as Administrator.") -- same text and
# color as a plain Write-Host call, also mirrored to the log so the reason survives
# a screen the user never saw (Safe Mode, an automatic reboot), not just the FAIL word.
function Write-ErrorLine {
    param([string]$Text)
    Write-Host "  [ERROR] $Text" -ForegroundColor Red
    Write-LogLine "  [ERROR] $Text"
}

function Write-WarningLine {
    param([string]$Text)
    Write-Host "  [WARNING] $Text" -ForegroundColor Yellow
    Write-LogLine "  [WARNING] $Text"
}

# Renders the outcome of a multi-item step whose items are already run --
# $StepResults = array of @{ Label; Ok; Error } (step-runner.ps1's shape).
# Collapses to "OK" when every item succeeded; on any failure, prints "PARTIAL"
# plus one line per item (succeeded ones too, so the failing one is easy to
# place among its neighbors) and the stored error for each failure.
# $PartialNote, if given, is shown once under the itemization (e.g. what the
# next stage will do about it). Returns $true when the step was partial, so
# the caller can fold that into its own $script:HasErrors.
function Write-StepResult {
    param([array]$StepResults, [string]$PartialNote)

    $failedResults = @($StepResults | Where-Object { -not $_.Ok })
    if ($failedResults.Count -eq 0) {
        Write-StepOk
        return $false
    }

    Write-Host "PARTIAL" -ForegroundColor Yellow
    Write-LogLine "  $script:CurrentStepHeader... PARTIAL"
    foreach ($stepResult in $StepResults) {
        if ($stepResult.Ok) {
            Write-Host "    [+] $($stepResult.Label)" -ForegroundColor Green
            Write-LogLine "    [+] $($stepResult.Label)"
        } else {
            Write-Host "    [~] $($stepResult.Label)" -ForegroundColor Yellow
            Write-Host "        $($stepResult.Error)" -ForegroundColor DarkGray
            Write-LogLine "    [~] $($stepResult.Label)"
            Write-LogLine "        $($stepResult.Error)"
        }
    }
    if ($PartialNote) {
        Write-Host "    $PartialNote" -ForegroundColor DarkGray
        Write-LogLine "    $PartialNote"
    }
    Write-Host ""
    return $true
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
