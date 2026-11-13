# log-file.ps1 -- optional plain-text mirror of the console step output (console-ui.ps1),
# written next to defender-backup.json. Check-Status.ps1 answers "what is true now"; this
# answers "what happened along the way" for a failure the user did not see (Safe Mode,
# an automatic reboot) and that they can hand to the agent for diagnosis.

$script:LogFilePath = $null

function Set-LogFilePath {
    param([string]$Path)
    $script:LogFilePath = $Path
}

# Tells the user where the details of a failed or partial run were written.
function Write-LogLocation {
    if (-not $script:LogFilePath) { return }
    Write-Host "  Log: $script:LogFilePath" -ForegroundColor DarkGray
}

function Write-LogLine {
    param([string]$Text)
    if (-not $script:LogFilePath) { return }
    try {
        [IO.File]::AppendAllText($script:LogFilePath, "$Text`r`n", [Text.UTF8Encoding]::new($false))
    } catch {
        # Best-effort: a locked or inaccessible log file must not block the operation itself.
    }
}
