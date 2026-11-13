# Capturing a child call in an expression buffers its console output; use script-scoped exit codes.
# Exit codes: 0 completed or declined, 1 action failed, 2 rejected before changes.
param(
    # PowerShell -File binds named switches with -, so slash flags are parsed as strings.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'console-ui.ps1')

function Write-UsageError {
    param([string]$Message)
    Write-Host ""
    Write-Host "  [ERROR] $Message" -ForegroundColor Red
    Write-Host "  Valid switches: /Status, /Disable, /Restore, /Unattended, /AllowReboot." -ForegroundColor DarkGray
    Write-Host ""
    exit 2
}

$Status = $false
$Disable = $false
$Restore = $false
$Unattended = $false
$AllowReboot = $false
$unknownArgument = $null
# PowerShell's switch statement compares strings case-insensitively by
# default -- matches cmd's own "if /i" flag comparisons.
foreach ($argument in $Arguments) {
    switch ($argument) {
        '/Status' { $Status = $true }
        '/Disable' { $Disable = $true }
        '/Restore' { $Restore = $true }
        '/Unattended' { $Unattended = $true }
        '/AllowReboot' { $AllowReboot = $true }
        default { if ($null -eq $unknownArgument) { $unknownArgument = $argument } }
    }
}
if ($null -ne $unknownArgument) {
    Write-UsageError "Unknown argument: $unknownArgument"
}

$actionSwitches = @($Status, $Disable, $Restore) | Where-Object { $_ }
if ($actionSwitches.Count -gt 1) {
    Write-UsageError 'Specify only one of /Status, /Disable or /Restore.'
}

$selectedAction = if ($Status) { 'Status' } elseif ($Disable) { 'Disable' } elseif ($Restore) { 'Restore' } else { $null }

# Unattended Disable and Restore require explicit consent to reboot.
if ($Unattended -and $selectedAction -in @('Disable', 'Restore') -and -not $AllowReboot) {
    Write-UsageError "/$selectedAction with /Unattended also needs /AllowReboot: it restarts the PC."
}

$script:ChildExitCode = $null

# Call as a bare statement to keep child console output from being captured.
function Invoke-ChildScript {
    param([string]$ScriptName, [string[]]$ScriptArgs = @())
    $scriptPath = Join-Path $PSScriptRoot $ScriptName
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath @ScriptArgs
    $script:ChildExitCode = $LASTEXITCODE
}

function Invoke-StatusAction {
    param([switch]$Unattended)
    $scriptArgs = @()
    if ($Unattended) { $scriptArgs += '-Unattended' }
    Invoke-ChildScript -ScriptName 'Check-Status.ps1' -ScriptArgs $scriptArgs
}

function Invoke-DisableAction {
    param([switch]$Unattended)
    $scriptArgs = @()
    if ($Unattended) { $scriptArgs += '-Unattended' }
    Invoke-ChildScript -ScriptName 'stage-normal.ps1' -ScriptArgs $scriptArgs
}

function Invoke-RestoreAction {
    param([switch]$Unattended)
    $scriptArgs = @()
    if ($Unattended) { $scriptArgs += '-Unattended' }
    Invoke-ChildScript -ScriptName 'restore-from-backup.ps1' -ScriptArgs $scriptArgs
}

# Disable reboots through Safe Mode; Restore reboots once.
function Confirm-MenuReboot {
    param([string]$Verb)
    Write-Host ""
    Write-Host "  This will $Verb. The PC restarts automatically, more than once -- save your work first." -ForegroundColor Yellow
    $answer = Read-Host '  Continue? (Y/N)'
    return $answer -in @('y', 'Y')
}

$script:MenuExitCode = $null

# Call as a bare statement so child console output is not captured.
function Show-Menu {
    $emptyStreak = 0
    while ($true) {
        Write-Host ''
        Write-Host '  Disable Defender'
        Sep
        Write-Host '  1) Check protection status'
        Write-Host '  2) Disable Windows Defender'
        Write-Host '  3) Restore Windows Defender'
        Write-Host '  0) Exit'
        Write-Host ''
        $choice = Read-Host '  Choice'
        # Redirected input can begin with a BOM or return null; Trim alone does not remove the BOM.
        if ($null -eq $choice) { $choice = '' }
        $choice = $choice.TrimStart([char]0xFEFF)
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $emptyStreak++
            # Closed input can return empty lines indefinitely rather than signal EOF.
            if ($emptyStreak -ge 3) {
                Write-Host '  No input received. Exiting.' -ForegroundColor Yellow
                $script:MenuExitCode = 2
                return
            }
            continue
        }
        $emptyStreak = 0
        switch ($choice.Trim()) {
            '1' { Invoke-StatusAction }
            '2' {
                if (Confirm-MenuReboot -Verb 'disable Windows Defender') {
                    Invoke-DisableAction
                    $script:MenuExitCode = $script:ChildExitCode
                    return
                }
            }
            '3' {
                if (Confirm-MenuReboot -Verb 'restore Windows Defender') {
                    Invoke-RestoreAction
                    $script:MenuExitCode = $script:ChildExitCode
                    return
                }
            }
            '0' { $script:MenuExitCode = 0; return }
            default { Write-Host '  Unrecognized choice.' -ForegroundColor Yellow }
        }
    }
}

if (-not $selectedAction) {
    if ($Unattended) {
        Write-UsageError 'Specify /Status, /Disable or /Restore with /Unattended.'
    }
    Show-Menu
    exit $script:MenuExitCode
}

if (-not $Unattended -and $selectedAction -in @('Disable', 'Restore')) {
    $verb = if ($selectedAction -eq 'Disable') { 'disable Windows Defender' } else { 'restore Windows Defender' }
    if (-not (Confirm-MenuReboot -Verb $verb)) { exit 0 }
}

switch ($selectedAction) {
    'Status' { Invoke-StatusAction -Unattended:$Unattended }
    'Disable' { Invoke-DisableAction -Unattended:$Unattended }
    'Restore' { Invoke-RestoreAction -Unattended:$Unattended }
}
exit $script:ChildExitCode
