# Read-only postconditions for restoration; no service activation before reboot.
function Get-RestoreRegistryState {
    param([string]$Path, [string]$Name)
    $parts = $Path -split '\\', 2
    $hive = switch ($parts[0]) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Unsupported verification hive: $Path" }
    }
    $key = $hive.OpenSubKey($parts[1])
    try {
        if ($null -eq $key) { return @{ KeyExists = $false; Exists = $false } }
        if ($key.GetValueNames() -notcontains $Name) { return @{ KeyExists = $true; Exists = $false } }
        return @{
            KeyExists = $true; Exists = $true
            Kind = $key.GetValueKind($Name)
            Value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    } finally { if ($null -ne $key) { $key.Dispose() } }
}

function Assert-RestoreRegistryValue {
    param([string]$Path, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind)
    $actual = Get-RestoreRegistryState $Path $Name
    if ($null -eq $Value -or $Value -is [DBNull]) {
        if ($actual.Exists) { throw "Restoration verification: $Path [$Name] should be absent." }
        return
    }
    if (-not $actual.Exists -or $actual.Kind -ne $Kind -or $actual.Value -cne $Value) {
        throw "Restoration verification: $Path [$Name] differs from the expected value or type."
    }
}

function Test-BackupServiceAbsenceRecorded {
    param($Backup, [string]$ServiceName, [string]$ControlSetName)
    if (-not $Backup -or $Backup.Services.PSObject.Properties.Name -notcontains $ServiceName) { return $false }
    $saved = $Backup.Services.$ServiceName
    if ($saved -is [pscustomobject]) {
        return ($saved.PSObject.Properties.Name -contains $ControlSetName) -and $null -eq $saved.$ControlSetName
    }
    return $null -eq $saved
}

# A service recorded as absent that exists now with any Start other than the
# disabled value was installed after Disable (a Windows or platform update).
# Disable never creates a service, so Restore leaves such a service as found.
function Test-ServiceAppearedAfterDisable {
    param([string]$Path)
    $state = Get-RestoreRegistryState $Path 'Start'
    return $state.KeyExists -and -not ($state.Exists -and $state.Value -eq 4)
}

function Assert-RestoredServices {
    param($Backup, [hashtable]$ServiceDefaults)
    $controlSets = @(Get-ControlSetTargets)
    foreach ($serviceName in $ServiceDefaults.Keys) {
        $saved = if ($Backup) { $Backup.Services.$serviceName } else { $null }
        foreach ($controlSet in $controlSets) {
            $recorded = $Backup -and $Backup.Services.PSObject.Properties.Name -contains $serviceName
            if ($saved -is [pscustomobject]) { $recorded = $saved.PSObject.Properties.Name -contains $controlSet }
            $expected = if ($saved -is [pscustomobject]) { $saved.$controlSet } else { $saved }
            $path = "HKLM\SYSTEM\$controlSet\Services\$serviceName"
            # Recorded absence must remain absence, including skipped protection steps.
            if ($recorded -and $null -eq $expected) {
                if (Test-ServiceAppearedAfterDisable $path) { continue }
                Assert-RestoreRegistryValue $path 'Start' $null DWord
                continue
            }
            if ($null -eq $expected) { $expected = $ServiceDefaults[$serviceName] }
            $actual = Get-RestoreRegistryState $path 'Start'
            if (-not $actual.KeyExists -and -not $recorded) { continue }
            Assert-RestoreRegistryValue $path 'Start' ([int]$expected) DWord
        }
    }
}

function Assert-RestoredRegistrySettings {
    param($Backup, [bool]$RestoreUserSettings)
    foreach ($entry in @(Get-ProtectedRegistryValues -IncludeUser:$RestoreUserSettings)) {
        if ($entry.Section -eq 'AttachmentWarning' -and $Backup -and $null -eq $Backup.AttachmentWarning) { continue }
        # Same legacy-field exemption as Restore-ProtectedRegistrySection: a
        # backup predating this field was never touched for it, so there is
        # nothing to verify either way.
        if ($Backup -and $Backup.($entry.Section) -and $script:LegacyOptionalSectionFields -and $script:LegacyOptionalSectionFields.ContainsKey($entry.Section) -and
            $entry.Field -in $script:LegacyOptionalSectionFields[$entry.Section] -and
            $Backup.($entry.Section).PSObject.Properties.Name -notcontains $entry.Field) { continue }
        $expected = Get-RestoreRegistryExpectedValue $Backup $entry
        Assert-RestoreRegistryValue (Get-ProtectedRegistryNativePath $entry) $entry.Name $expected $entry.Kind
    }
    $autorun = if ($Backup) { $Backup.SecurityHealthAutorun } else { @{ Value='%windir%\system32\SecurityHealthSystray.exe'; Type='ExpandString' } }
    $value = if ($autorun -is [string]) { $autorun } elseif ($autorun) { $autorun.Value } else { $null }
    $kind = if ($autorun.Type -in @('String', 'ExpandString')) { $autorun.Type }
            elseif ($value -like '*%*') { 'ExpandString' } else { 'String' }
    Assert-RestoreRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth' $value $kind
    Assert-RestoreRegistryValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' '*LauncherSafe' $null String

    $eppPaths = @{
        Star = '*'; Drive = 'Drive'; Directory = 'Directory'; DirBg = 'Directory\Background'; Folder = 'Folder'
    }
    foreach ($name in $eppPaths.Keys) {
        $path = "HKLM\SOFTWARE\Classes\$($eppPaths[$name])\shellex\ContextMenuHandlers\EPP"
        $expected = if ($Backup) { $Backup.EppContextMenu.$name } else { '{09A47860-11B0-4DA5-AFA5-26D86198A780}' }
        $actual = Get-RestoreRegistryState $path ''
        if ($null -eq $expected) {
            if ($actual.KeyExists) { throw "Restoration verification: $path should be absent." }
            continue
        }
        Assert-RestoreRegistryValue $path '' $expected String
    }
}

function Assert-RestoredTasks {
    param($Backup)
    # Enumerate successfully before deciding that a task is absent.
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $definitions = @{
        CacheMaintenance = '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance'
        Cleanup = '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup'
        ScheduledScan = '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan'
        Verification = '\Microsoft\Windows\Windows Defender\Windows Defender Verification'
        RecoverabilityToast = '\Microsoft\Windows\AccountHealth\RecoverabilityToastTask'
    }
    foreach ($name in $definitions.Keys) {
        $expected = if ($Backup) { $Backup.ScheduledTasks.$name } else { $null }
        $task = @($tasks | Where-Object { ($_.TaskPath + $_.TaskName) -eq $definitions[$name] })
        if ($null -eq $expected) {
            if ($Backup -and $Backup.ScheduledTasks.PSObject.Properties.Name -contains $name) {
                if ($task.Count -ne 0) { throw "Restoration verification: scheduled task $name should be absent." }
                continue
            }
            $expected = $true
        }
        if ($task.Count -ne 1 -or [bool]$task[0].Settings.Enabled -ne [bool]$expected) {
            throw "Restoration verification: scheduled task $name differs from the expected state."
        }
    }
}

function Assert-RestoredSecurity {
    param($Backup)
    if (-not $Backup -or $Backup.SchemaVersion -lt 4) { return }
    $actual = Get-SecurityState
    foreach ($property in $Backup.SecurityState.Registry.PSObject.Properties) {
        $presentDescriptor = $actual.Registry[$property.Name]
        # Absent when the backup was taken and present now: installed later, never touched.
        if ($null -eq $property.Value -and $null -ne $presentDescriptor) { continue }
        $expectedDescriptor = Get-ComparableSecurityDescriptor $property.Value
        $actualDescriptor = Get-ComparableSecurityDescriptor $presentDescriptor
        if ($expectedDescriptor -cne $actualDescriptor) {
            throw "Restoration verification: registry security differs for $($property.Name)."
        }
    }
    if ((Get-ComparableSecurityDescriptor $Backup.SecurityState.SmartScreen) -cne
        (Get-ComparableSecurityDescriptor $actual.SmartScreen)) {
        throw 'Restoration verification: SmartScreen security differs from the backup.'
    }
}

function Assert-RestoredSettings {
    param($Backup, [bool]$RestoreUserSettings, [hashtable]$ServiceDefaults)
    Assert-RestoredServices $Backup $ServiceDefaults
    Assert-RestoredRegistrySettings $Backup $RestoreUserSettings
    Assert-RestoredTasks $Backup
    Assert-RestoredSecurity $Backup
}
