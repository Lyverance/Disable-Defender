# run-lock.ps1 -- excludes a second concurrent Disable/Restore run from making any
# change while one is already in progress. This is a different problem from
# operation-state.json's unfinished-operation marker (Show-UnfinishedOperationWarning):
# that one answers "did a previous run end without finishing", and only warns, because
# a crashed run must still be resumable by re-running. This one answers "is another
# run alive right now", and must refuse outright -- a plain marker file would need a
# separate check-then-create step that two processes could both pass before either
# writes the file. An OS-held exclusive file handle has no such gap: the second
# attempt to open the same path with FileShare.None fails immediately. The holding
# process's handle is also released automatically if it dies without ever calling
# Exit-RunLock (crash, kill, power loss), since the OS reclaims all of a process's
# handles on exit -- so a stale lock can never block the next run.
#
# Scope: only the two entry points a person can launch directly while another is
# already running (Defender.cmd /Disable -> stage-normal.ps1, and Defender.cmd
# /Restore -> restore-from-backup.ps1) share this lock. stage-safe.ps1's Safe Mode pass is started
# once automatically via RunOnce, not by a second concurrent invocation of the same
# command, so it does not take this lock.
#
# The lock path itself must NOT depend on $PSScriptRoot. The tool is portable --
# nothing stops a person from downloading or copying it into two different folders
# (or two different drives) and launching both. A path under the script's own folder
# would give each copy its own run.lock and let two copies change the same machine's
# Defender settings at once, exactly what this lock exists to prevent. Get-RunLockPath
# below returns one fixed, machine-wide path instead, so every copy -- regardless of
# where it was extracted -- contends for the same file. ProgramData is writable only
# by an administrator, which this tool already requires for every change it makes;
# this is a different tradeoff from the portable per-folder backup/operation-state
# files, which must stay with their folder because they are per-copy user data,
# not a cross-copy synchronization primitive.

function Get-RunLockPath {
    return (Join-Path $env:ProgramData 'Disable-Defender\run.lock')
}

function Enter-RunLock {
    param([string]$Path)
    try {
        $directory = Split-Path -Parent $Path
        if ($directory) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
        return [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch [IO.IOException] {
        return $null
    }
}

function Exit-RunLock {
    param([IO.FileStream]$Lock)
    if ($null -ne $Lock) { $Lock.Dispose() }
}
