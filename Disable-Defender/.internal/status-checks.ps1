function RegValue($path, $name, $expected, [Microsoft.Win32.RegistryValueKind]$expectedType) {
    $entry = Read-RegEntry $path $name
    if (-not $entry.Readable -or -not $entry.Exists) { return $false }
    return ($entry.Type -eq $expectedType.ToString() -and $entry.Value -eq $expected)
}

# Reads one registry value via the .NET API (not the Get-ItemProperty cmdlet).
# Readable=$false means the read itself failed (access denied or similar) --
# Exists/Value/Type are meaningless then and must NOT be treated as a
# confirmed absence: a denied read and a genuinely absent value look the same
# from the caller's side unless this distinction is kept.
function Read-RegEntry($path, $name) {
    $hive = switch -Regex ($path) {
        '^HKLM:\\' { [Microsoft.Win32.Registry]::LocalMachine }
        '^HKCU:\\' { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported registry path: $path" }
    }
    $subkeyPath  = $path.Substring($path.IndexOf('\') + 1)
    $registryKey = $null
    try {
        $registryKey = $hive.OpenSubKey($subkeyPath)
        if ($null -eq $registryKey -or $registryKey.GetValueNames() -notcontains $name) {
            return [pscustomobject]@{ Readable = $true; Exists = $false; Value = $null; Type = $null }
        }
        return [pscustomobject]@{
            Readable = $true
            Exists   = $true
            # DoNotExpandEnvironmentNames: an ExpandString backup stores the raw
            # command (e.g. "%windir%\..."); comparing against the expanded form
            # would never match.
            Value    = $registryKey.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Type     = $registryKey.GetValueKind($name).ToString()
        }
    } catch {
        return [pscustomobject]@{ Readable = $false; Exists = $false; Value = $null; Type = $null }
    } finally {
        if ($null -ne $registryKey) { $registryKey.Close() }
    }
}

# Same as Read-RegEntry, for a key's default (unnamed) value -- the EPP
# context-menu handlers store their GUID there. $subkeyPath is HKLM-relative,
# matching the existing KeyAbsent/EPP callers.
function Read-RegKeyDefault($subkeyPath) {
    Read-RegEntry ('HKLM:\' + $subkeyPath) ''
}

# $true = confirmed absent, $false = confirmed present, $null = the read
# itself failed -- callers must not treat $null as either state.
function RegAbsent($path, $name) {
    $entry = Read-RegEntry $path $name
    if (-not $entry.Readable) { return $null }
    return (-not $entry.Exists)
}

# Checks whether the KEY itself exists, not whether its default value does --
# stage-safe.ps1's EPP removal deletes the whole subkey via
# DeleteSubKeyTree, so "removed" must mean the key is gone, not merely that
# its default value is unset. (Read-RegKeyDefault/Read-RegEntry check the
# value, which CheckRestoredPresent still needs for GUID comparison --
# that is a different question from whether the key was removed.)
function Read-RegKey($path) {
    $hive = switch -Regex ($path) {
        '^HKLM:\\' { [Microsoft.Win32.Registry]::LocalMachine }
        '^HKCU:\\' { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported registry path: $path" }
    }
    $subkeyPath  = $path.Substring($path.IndexOf('\') + 1)
    $registryKey = $null
    try {
        $registryKey = $hive.OpenSubKey($subkeyPath)
        return [pscustomobject]@{ Readable = $true; Exists = ($null -ne $registryKey) }
    } catch {
        return [pscustomobject]@{ Readable = $false; Exists = $false }
    } finally {
        if ($null -ne $registryKey) { $registryKey.Close() }
    }
}

function KeyAbsent($subkeyPath) {
    $entry = Read-RegKey ('HKLM:\' + $subkeyPath)
    if (-not $entry.Readable) { return $null }
    return (-not $entry.Exists)
}

# Reports a should-be-absent check against RegAbsent's/KeyAbsent's tri-state
# result: absent passes, present fails, and a read failure is its own
# distinct failure rather than being silently accepted as "absent".
function CheckAbsent($label, $absentResult) {
    if ($null -eq $absentResult) {
        Check ($label + ' - cannot verify (read denied)') $false
    } elseif ($absentResult) {
        CheckOK ($label + ' - absent')
    } else {
        Check ($label + ' - should be absent') $false
    }
}

# Reports a should-be-present check with no recorded expected value to
# compare against (e.g. a limited comparison with no usable backup).
function CheckPresent($label, $absentResult) {
    if ($null -eq $absentResult) {
        Check ($label + ' - cannot verify (read denied)') $false
    } else {
        Check ($label + ' - present') (-not $absentResult)
    }
}

# Reports a should-be-present check against the backed-up value (and,
# when the backup recorded one, its registry type) -- not just presence.
# $expectedType may be $null for backups that predate type tracking.
function CheckRestoredPresent($label, $entry, $expectedValue, $expectedType) {
    if (-not $entry.Readable) {
        Check ($label + ' - cannot verify (read denied)') $false
    } elseif (-not $entry.Exists) {
        Check ($label + ' - missing') $false
    } elseif ($entry.Value -ne $expectedValue) {
        Check ($label + ' - differs from backup') $false
    } elseif ($expectedType -and $entry.Type -ne $expectedType) {
        Check ($label + ' - type differs from backup') $false
    } else {
        Check ($label + ' = backup') $true
    }
}

function ServiceDisabled($svcName) {
    # Read directly from registry -- Get-Service reads from SCM which may not
    # reflect registry changes made in Safe Mode until next full SCM init.
    # Start=4 means Disabled.
    # A denied or failed read must surface, not read as "disabled"; only a
    # genuinely absent key or value counts as disabled.
    $serviceKey = $null
    try {
        $serviceKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$svcName")
        if ($null -eq $serviceKey) { return $true }
        $startValue = $serviceKey.GetValue('Start', $null)
    } finally {
        if ($null -ne $serviceKey) { $serviceKey.Close() }
    }
    if ($null -eq $startValue) { return $true }
    return ($startValue -eq 4)
}

# A service the backup records as absent but that exists now was installed after
# Disable (a platform update added MDCoreSvc): Restore leaves it as found, so it
# passes unless it is still disabled (Start 4, the value Disable writes).
function Test-ServiceInstalledAfterDisable($ExpectedStart, [bool]$KeyExists, $ActualStart) {
    return $null -eq $ExpectedStart -and $KeyExists -and $ActualStart -ne 4
}
function Test-RestoredServiceStatus($Backup, [string]$ServiceName, [bool]$KeyExists, $Actual, $Expected) {
    $recorded = $Backup -and $Backup.Services.PSObject.Properties.Name -contains $ServiceName
    if ($recorded -and $Backup.Services.$ServiceName -is [pscustomobject]) {
        $recorded = $Backup.Services.$ServiceName.PSObject.Properties.Name -contains 'CurrentControlSet'
    }
    if (-not $KeyExists -and -not $recorded) { return $true }
    return $Actual -eq $Expected
}

# v3 backups store a value per ControlSet name; v2/legacy backups store one value.
# Only CurrentControlSet matters here -- that is what ServiceDisabled/actualStart read.
function Get-ExpectedServiceStart($backup, $svcName, $defaultValue) {
    if (-not $backup -or $backup.Services.PSObject.Properties.Name -notcontains $svcName) {
        return $defaultValue
    }
    $backupValue = $backup.Services.$svcName
    # Recorded absence is original state, not an instruction to invent a default.
    if ($null -eq $backupValue) { return $null }
    if ($backupValue -is [System.Management.Automation.PSCustomObject]) {
        if ($backupValue.PSObject.Properties.Name -notcontains 'CurrentControlSet') {
            return $defaultValue
        }
        $currentControlSetValue = $backupValue.CurrentControlSet
        if ($null -eq $currentControlSetValue) { return $null }
        return [int]$currentControlSetValue
    }
    return [int]$backupValue
}

# $null = the read itself failed (e.g. the Task Scheduler service is
# unreachable) -- callers must not treat that the same as a confirmed
# state, the same distinction RegAbsent/KeyAbsent make for the registry.
# -TaskPath/-TaskName with -ErrorAction SilentlyContinue swallowed both a
# genuinely absent task AND a real enumeration failure into the same empty
# result; enumerating all tasks first (failing loudly on a real error) and
# filtering after tells them apart.
function TaskDisabled($taskPath, $taskName) {
    try {
        $taskObject = Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath -eq $taskPath -and $_.TaskName -eq $taskName
        }
    } catch {
        return $null
    }
    if ($null -eq $taskObject) { return $true }
    return ($taskObject.State -eq 'Disabled')
}

# Reports a check against TaskDisabled's tri-state result: a read failure is
# its own distinct failure, never silently accepted as a match.
function CheckTaskState($label, $taskDisabledResult, [bool]$expectedDisabled) {
    if ($null -eq $taskDisabledResult) {
        Check ($label + ' - cannot verify (read denied)') $false
    } else {
        Check $label ($taskDisabledResult -eq $expectedDisabled)
    }
}

# Checks that the current DWORD registry value matches the backup.
# If backup was null, the key should be absent.
function CheckRestoredDword($label, $regPath, $regName, $backupVal) {
    if ($null -eq $backupVal -or $backupVal -is [System.DBNull]) {
        CheckAbsent $label (RegAbsent $regPath $regName)
    } else {
        Check ($label + ' = ' + $backupVal) (RegValue $regPath $regName ([int]$backupVal) DWord)
    }
}

function CheckRestoredSz($label, $regPath, $regName, $backupVal) {
    if ($null -eq $backupVal -or $backupVal -is [System.DBNull]) {
        CheckAbsent $label (RegAbsent $regPath $regName)
    } else {
        Check ($label + " = '" + $backupVal + "'") (RegValue $regPath $regName $backupVal String)
    }
}

# Status lines for the catalog entries of one backup section: the disabled
# value while protection is off, the backed-up value (or absence) after a
# restore.
function CheckProtectedRegistrySection($section, $defenderOff, $backup, $checkUserSettings) {
    foreach ($entry in @(Get-ProtectedRegistryValues -IncludeUser:$checkUserSettings)) {
        if ($entry.Section -ne $section) { continue }
        if (-not (Test-RegistryEntryRecorded $backup $entry)) { continue }
        $path = "$($entry.Hive):\$($entry.Path)"
        $expectDisabled = $defenderOff
        if ($expectDisabled) {
            Check $entry.DisabledLabel (RegValue $path $entry.Name $entry.DisabledValue $entry.Kind)
        } elseif ($entry.Kind -eq 'String') {
            CheckRestoredSz $entry.StatusLabel $path $entry.Name (Get-BackedUpRegistryValue $backup $entry)
        } else {
            CheckRestoredDword $entry.StatusLabel $path $entry.Name (Get-BackedUpRegistryValue $backup $entry)
        }
    }
}

