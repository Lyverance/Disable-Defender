# Tracks which stage of a Disable or Restore operation last ran, in a file that
# survives a reboot. A backup file alone cannot tell a later run (or Check-Status)
# whether the operation that created it ever reached its last stage -- this can.
# The state is cleared on a normal full run, so its mere presence means the
# previous run of that operation did not reach its own last stage.
$script:MaximumOperationStateBytes = 64KB

# Move-Item -Force and [IO.File]::Replace both delete or rename the existing
# marker before the replacement lands -- a real, measured window where the
# marker does not exist at all.
# MoveFileEx with MOVEFILE_REPLACE_EXISTING performs the swap as a single
# atomic NTFS rename with no such window, and its P/Invoke signature works
# unchanged on both Windows PowerShell 5.1 (.NET Framework) and pwsh.
# The type registration lives inside this function, not at file scope, so a
# caller that dot-sources only the function definitions still gets it.
function Move-FileAtomicReplace {
    param([string]$SourcePath, [string]$DestinationPath)
    if (-not ([Management.Automation.PSTypeName]'DisableDefenderNative.AtomicFileReplace').Type) {
        Add-Type -Namespace DisableDefenderNative -Name AtomicFileReplace -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);
'@
    }
    $moveFileExReplaceExisting = 0x1
    $moveFileExWriteThrough    = 0x8
    $succeeded = [DisableDefenderNative.AtomicFileReplace]::MoveFileEx($SourcePath, $DestinationPath, ($moveFileExReplaceExisting -bor $moveFileExWriteThrough))
    if (-not $succeeded) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new($errorCode, "MoveFileEx failed replacing $DestinationPath")
    }
}

function Get-OperationState {
    [CmdletBinding()]
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($stream.Length -eq 0 -or $stream.Length -gt $script:MaximumOperationStateBytes) {
                throw 'Operation state file is empty or oversized.'
            }
            $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true)
            try { $rawJson = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        $state = ConvertFrom-Json -InputObject $rawJson -ErrorAction Stop
        $hasOperation = $state.PSObject.Properties.Name -contains 'Operation'
        $hasStage     = $state.PSObject.Properties.Name -contains 'Stage'
        if (-not $hasOperation -or -not $hasStage -or
            $state.Operation -isnot [string] -or $state.Stage -isnot [string] -or
            [string]::IsNullOrWhiteSpace($state.Operation) -or [string]::IsNullOrWhiteSpace($state.Stage)) {
            throw 'Operation state is missing Operation or Stage.'
        }
        return [pscustomobject]@{
            Operation = $state.Operation
            Stage     = $state.Stage
            StartedAt = $state.StartedAt
            UpdatedAt = $state.UpdatedAt
            Readable  = $true
        }
    } catch {
        # The file's existence is itself the signal an operation did not finish --
        # losing that signal to a parse error would hide the one case this exists for.
        return [pscustomobject]@{
            Operation = 'Unknown'
            Stage     = 'Unknown'
            StartedAt = $null
            UpdatedAt = $null
            Readable  = $false
        }
    }
}

function Set-OperationState {
    param([string]$Path, [string]$Operation, [string]$Stage)
    $existing  = Get-OperationState $Path
    $startedAt = if ($existing -and $existing.Readable -and $existing.Operation -eq $Operation -and $existing.StartedAt) {
        $existing.StartedAt
    } else {
        Get-Date -Format 'o'
    }
    $state = @{
        Operation = $Operation
        Stage     = $Stage
        StartedAt = $startedAt
        UpdatedAt = (Get-Date -Format 'o')
    }
    $temporaryPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $state -Depth 3
        [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($true))
        Move-FileAtomicReplace -SourcePath $temporaryPath -DestinationPath $Path
    } finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Clear-OperationState {
    param([string]$Path)
    Remove-Item -LiteralPath $Path -ErrorAction SilentlyContinue
}
