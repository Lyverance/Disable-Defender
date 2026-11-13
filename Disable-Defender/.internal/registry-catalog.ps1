# The registry values this tool captures, changes and restores, listed once.
# Backup validation, restore and restore verification read this list instead
# of each carrying its own copy, so a value added or changed here reaches all
# of them together.
#
# Section/Field locate the value inside the backup file; Scope 'User' entries
# live in HKCU and are skipped when the backup belongs to another account.
# Services, scheduled tasks, EPP handlers and the autorun entry differ in
# shape (several ControlSets, enabled flag, default GUID, value type) and stay
# in their own lists rather than behind a Kind switch.

$script:SecurityCenterNotificationPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance'

# Label is the console name of the step in normal mode; StatusLabel and
# DisabledLabel are the lines Check-Status prints after a restore and while
# protection is off; DisabledValue is what the tool writes. DisableGroup selects the normal-mode step that writes the
# value; FinalizeInSafeMode marks the values the Safe Mode pass writes again
# -- needed for the two bare 'Microsoft\Security Center' values and the
# SecurityAndMaintenance toast, which Tamper Protection can revert if written
# only once on a live system. HideSystray and DisableHealthCenter do not need
# it; the Notifications policy pair below follows their pattern
# (same Policies\...\Windows Defender Security Center branch) but is marked
# FinalizeInSafeMode nonetheless -- the extra Safe Mode write costs nothing and
# avoids relying on an unconfirmed
# assumption for a setting this tool depends on to suppress the "Defender is
# off" toast.
$script:ProtectedRegistryValues = @(
    @{ Section = 'SecurityCenter'; Field = 'AntiVirusDisableNotify'; Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Security Center'; Name = 'AntiVirusDisableNotify'; Kind = 'DWord'
       Label = 'AntiVirusDisableNotify'; StatusLabel = 'AntiVirusDisableNotify'; DisabledLabel = 'AntiVirusDisableNotify = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $true }
    @{ Section = 'SecurityCenter'; Field = 'AntiVirusOverride';      Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Security Center'; Name = 'AntiVirusOverride';      Kind = 'DWord'
       Label = 'AntiVirusOverride'; StatusLabel = 'AntiVirusOverride'; DisabledLabel = 'AntiVirusOverride = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $true }
    @{ Section = 'SecurityCenter'; Field = 'ToastNotifyEnabled';     Scope = 'Machine'; Hive = 'HKLM'; Path = $script:SecurityCenterNotificationPath; Name = 'Enabled'; Kind = 'DWord'
       Label = 'Toast notifications'; StatusLabel = 'SecurityAndMaintenance toast'; DisabledLabel = 'SecurityAndMaintenance toast Off'; DisabledValue = 0; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $true }
    @{ Section = 'SecurityCenter'; Field = 'ToastNotifyEnabledUser'; Scope = 'User';    Hive = 'HKCU'; Path = $script:SecurityCenterNotificationPath; Name = 'Enabled'; Kind = 'DWord'
       Label = 'Toast notifications (user)'; StatusLabel = 'SecurityAndMaintenance toast (user)'; DisabledLabel = 'SecurityAndMaintenance toast Off (user)'; DisabledValue = 0; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $false }
    # These policies suppress Security Center notifications while preserving wscsvc monitoring.
    @{ Section = 'SecurityCenter'; Field = 'DisableNotifications';         Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableNotifications'; Kind = 'DWord'
       Label = 'DisableNotifications'; StatusLabel = 'DisableNotifications'; DisabledLabel = 'DisableNotifications = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $true }
    @{ Section = 'SecurityCenter'; Field = 'DisableEnhancedNotifications'; Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableEnhancedNotifications'; Kind = 'DWord'
       Label = 'DisableEnhancedNotifications'; StatusLabel = 'DisableEnhancedNotifications'; DisabledLabel = 'DisableEnhancedNotifications = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $true }
    @{ Section = 'SmartScreen';    Field = 'PolicyValue';            Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen'; Kind = 'DWord'
       Label = 'Policy (EnableSmartScreen)'; StatusLabel = 'EnableSmartScreen'; DisabledLabel = 'EnableSmartScreen = 0'; DisabledValue = 0; DisableGroup = 'SmartScreen'; FinalizeInSafeMode = $true }
    @{ Section = 'SmartScreen';    Field = 'ExplorerValue';          Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Name = 'SmartScreenEnabled'; Kind = 'String'
       Label = 'Explorer (SmartScreenEnabled)'; StatusLabel = 'SmartScreenEnabled'; DisabledLabel = 'SmartScreenEnabled = Off'; DisabledValue = 'Off'; DisableGroup = 'SmartScreen'; FinalizeInSafeMode = $true }
    @{ Section = 'SmartScreen';    Field = 'AppHostValue';           Scope = 'User';    Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\AppHost'; Name = 'EnableWebContentEvaluation'; Kind = 'DWord'
       Label = 'AppHost (WebContentEvaluation)'; StatusLabel = 'EnableWebContentEvaluation'; DisabledLabel = 'EnableWebContentEvaluation = 0'; DisabledValue = 0; DisableGroup = 'SmartScreen'; FinalizeInSafeMode = $true }
    @{ Section = 'Systray';        Field = 'HideSystray';            Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray'; Name = 'HideSystray'; Kind = 'DWord'
       Label = 'HideSystray'; StatusLabel = 'HideSystray'; DisabledLabel = 'HideSystray = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $false }
    @{ Section = 'Systray';        Field = 'DisableHealthCenter';    Scope = 'Machine'; Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\HealthCenter'; Name = 'DisableHealthCenter'; Kind = 'DWord'
       Label = 'DisableHealthCenter'; StatusLabel = 'DisableHealthCenter'; DisabledLabel = 'DisableHealthCenter = 1'; DisabledValue = 1; DisableGroup = 'SecurityCenter'; FinalizeInSafeMode = $false }
    # Internet zone action 0x1806 controls the downloaded-file warning; older backups leave it untouched.
    @{ Section = 'AttachmentWarning'; Field = 'ZoneUnsafeFileLaunch';  Scope = 'User';    Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'; Name = '1806'; Kind = 'DWord'
       Label = 'Downloaded-file warning (zone 1806)'; StatusLabel = '1806 (unsafe-file launch)'; DisabledLabel = '1806 = 0 (no prompt)'; DisabledValue = 0; DisableGroup = 'AttachmentWarning'; FinalizeInSafeMode = $false }
)

function Get-ProtectedRegistryValues {
    param([switch]$IncludeUser)
    foreach ($entry in $script:ProtectedRegistryValues) {
        if ($entry.Scope -eq 'User' -and -not $IncludeUser) { continue }
        $entry
    }
}

# Backup-file schema for the registry sections: section name -> field -> kind.
function Get-ProtectedRegistrySections {
    $sections = @{}
    foreach ($entry in $script:ProtectedRegistryValues) {
        if (-not $sections.ContainsKey($entry.Section)) { $sections[$entry.Section] = @{} }
        $sections[$entry.Section][$entry.Field] = $entry.Kind
    }
    return $sections
}

# The value the backup recorded for one catalog entry. A missing backup or a
# missing section yields $null (nothing recorded), never a default: 0, $false
# and '' are recorded values and come back unchanged.
function Get-BackedUpRegistryValue {
    param($Backup, [hashtable]$Entry)
    if (-not $Backup) { return $null }
    $section = $Backup.($Entry.Section)
    if (-not $section) { return $null }
    return $section.($Entry.Field)
}

# Missing backup uses only defaults established on the clean test system.
function Get-RestoreRegistryExpectedValue {
    param($Backup, [hashtable]$Entry)
    if ($null -eq $Backup -and $Entry.Section -eq 'SmartScreen') {
        if ($Entry.Field -eq 'PolicyValue') { return 1 }
        if ($Entry.Field -eq 'ExplorerValue') { return 'Warn' }
    }
    return Get-BackedUpRegistryValue $Backup $Entry
}

# Old backups cannot restore settings they did not record.
function Test-RegistryEntryRecorded {
    param($Backup, [hashtable]$Entry)
    if ($null -eq $Backup) { return $true }
    $section = $Backup.($Entry.Section)
    if ($null -eq $section) { return $false }
    return ($section.PSObject.Properties.Name -contains $Entry.Field)
}

# Native registry path ('HKLM\...') the restore and verification code uses.
function Get-ProtectedRegistryNativePath {
    param([hashtable]$Entry)
    return "$($Entry.Hive)\$($Entry.Path)"
}

# Arguments for `reg add` that write the disabled value of one entry. The
# values stay strings: reg.exe takes them as text and the type switch decides
# how it stores them.
function Get-ProtectedRegistryDisableArguments {
    param([hashtable]$Entry)
    $registryType = if ($Entry.Kind -eq 'String') { 'REG_SZ' } else { 'REG_DWORD' }
    return @{
        Path  = Get-ProtectedRegistryNativePath $Entry
        Name  = $Entry.Name
        Type  = $registryType
        Value = [string]$Entry.DisabledValue
    }
}
