# Keep backup validation identical for creation, restoration and status checks.
. (Join-Path $PSScriptRoot 'security-state.ps1')
. (Join-Path $PSScriptRoot 'registry-catalog.ps1')
$script:BackupSchemaVersion = 6
# Older backups cannot provide an exact security rollback; missing newer fields must not change live values.
$script:SupportedBackupSchemaVersions = @(2, 3, 4, 5, 6)
# Fields added to an existing section after it already shipped -- a backup
# from before the field existed lacks it structurally, not "recorded as
# absent"; Assert-BackupState must not require it, and the corresponding
# restore/verification code must not treat its absence as license to delete
# or expect absence of the live value either.
$script:LegacyOptionalSectionFields = @{
    SecurityCenter = @('DisableNotifications', 'DisableEnhancedNotifications')
}
$script:MaximumBackupBytes = 1MB
# Matches every name Get-ControlSetTargets can produce (the alias plus any concrete
# ControlSetNNN), regardless of which ones exist on this machine right now -- a backup
# taken on different hardware can legitimately carry a different concrete set.
$script:ControlSetNamePattern = '^(CurrentControlSet|ControlSet\d{3})$'

# Targets for reading/writing a service's Start value: the alias plus every concrete
# ControlSet found on this machine. CurrentControlSet and the concrete set it resolves to
# can diverge across boots (Select\Current vs Select\Default/LastKnownGood), so both are
# tracked rather than assumed identical.
function Get-ControlSetTargets {
    $targets = [System.Collections.Generic.List[string]]@('CurrentControlSet')
    foreach ($controlSetIndex in 1..3) {
        $csName          = 'ControlSet{0:D3}' -f $controlSetIndex
        $controlSetProbe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName")
        if ($null -ne $controlSetProbe) {
            $controlSetProbe.Close()
            $targets.Add($csName)
        }
    }
    return $targets
}

function Get-BackupIdentity {
    $machineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { $userSid = $windowsIdentity.User.Value } finally { $windowsIdentity.Dispose() }
    if ([string]::IsNullOrWhiteSpace($machineGuid) -or [string]::IsNullOrWhiteSpace($userSid)) {
        throw 'Cannot identify this Windows installation and user.'
    }
    return @{ MachineGuid = $machineGuid; UserSid = $userSid }
}

function Assert-BackupObject {
    param($Value, [string]$Name)
    if ($Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw "Backup field $Name must be an object."
    }
}

function Assert-BackupValue {
    param($Value, [string]$Kind, [string]$Name)
    if ($null -eq $Value) { return }
    $isInteger = $Value -is [int] -or $Value -is [long]
    $valid = switch ($Kind) {
        'Start' { $isInteger -and $Value -ge 0 -and $Value -le 4 }
        'Dword' { $isInteger -and $Value -ge [int]::MinValue -and $Value -le [uint32]::MaxValue }
        'Boolean' { $Value -is [bool] }
        'String' { $Value -is [string] }
    }
    if (-not $valid) { throw "Invalid $Kind value in backup field $Name." }
}

function Assert-BackupState {
    param($Backup)
    Assert-BackupObject $Backup 'root'
    $timestamp = [datetime]::MinValue
    if ($Backup.Timestamp -isnot [string] -or -not [datetime]::TryParse(
        $Backup.Timestamp, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind, [ref]$timestamp)) {
        throw 'Backup Timestamp is missing or invalid.'
    }
    $hasVersion = $Backup.PSObject.Properties.Name -contains 'SchemaVersion'
    if (-not $hasVersion -and $Backup.PSObject.Properties.Name -contains 'Identity') {
        throw 'Backup SchemaVersion is missing from an identified backup.'
    }
    $versionIsInteger = $Backup.SchemaVersion -is [int] -or $Backup.SchemaVersion -is [long]
    if ($hasVersion -and (-not $versionIsInteger -or $Backup.SchemaVersion -notin $script:SupportedBackupSchemaVersions)) {
        throw 'Unsupported backup SchemaVersion.'
    }
    # Unversioned (pre-v2) and v2 backups store one Start value per service;
    # v3 stores a value per ControlSet name -- see Get-ControlSetTargets.
    $schemaVersion = if ($hasVersion) { [int]$Backup.SchemaVersion } else { 0 }

    Assert-BackupObject $Backup.Services 'Services'
    if ($Backup.Services.PSObject.Properties.Name -notcontains 'WinDefend') {
        throw 'Backup Services.WinDefend is missing.'
    }
    foreach ($property in $Backup.Services.PSObject.Properties) {
        Assert-BackupServiceStart $property.Value $schemaVersion "Services.$($property.Name)"
    }

    $sections = Get-ProtectedRegistrySections
    $sections.ScheduledTasks = @{ CacheMaintenance='Boolean'; Cleanup='Boolean'; ScheduledScan='Boolean'; Verification='Boolean'; RecoverabilityToast='Boolean' }
    $sections.EppContextMenu = @{ Star='String'; Drive='String'; Directory='String'; DirBg='String'; Folder='String' }
    if ($hasVersion) { Assert-BackupServices $Backup.Services }
    foreach ($sectionName in $sections.Keys) {
        # Older backups predate this section; if present it must still be complete.
        if ($sectionName -eq 'AttachmentWarning' -and $schemaVersion -lt 5 -and $Backup.PSObject.Properties.Name -notcontains $sectionName) { continue }
        $sectionFields = $sections[$sectionName]
        if ($schemaVersion -lt 6 -and $script:LegacyOptionalSectionFields.ContainsKey($sectionName)) {
            $sectionFields = $sectionFields.Clone()
            foreach ($legacyField in $script:LegacyOptionalSectionFields[$sectionName]) { $sectionFields.Remove($legacyField) }
        }
        Assert-BackupSection $Backup.$sectionName $sectionName $sectionFields $hasVersion
    }
    Assert-BackupAutorun $Backup.SecurityHealthAutorun $hasVersion
    if ($schemaVersion -ge 4) { Assert-SecurityState $Backup.SecurityState }
}

function Assert-BackupServiceStart {
    param($Value, [int]$SchemaVersion, [string]$Name)
    if ($null -eq $Value) { return }
    if ($SchemaVersion -ge 3) {
        Assert-BackupObject $Value $Name
        $controlSetProperties = @($Value.PSObject.Properties)
        if ($controlSetProperties.Count -eq 0) { throw "Backup field $Name has no ControlSet entries." }
        foreach ($controlSetProperty in $controlSetProperties) {
            if ($controlSetProperty.Name -notmatch $script:ControlSetNamePattern) {
                throw "Backup field $Name has an unrecognized ControlSet name '$($controlSetProperty.Name)'."
            }
            Assert-BackupValue $controlSetProperty.Value 'Start' "$Name.$($controlSetProperty.Name)"
        }
    } else {
        Assert-BackupValue $Value 'Start' $Name
    }
}

function Assert-BackupServices {
    param($Services)
    $serviceNames = @('WinDefend', 'WdFilter', 'MDCoreSvc', 'WdBoot', 'WdNisSvc', 'WdNisDrv', 'Sense', 'webthreatdefsvc', 'webthreatdefusersvc', 'wscsvc')
    foreach ($serviceName in $serviceNames) {
        if ($Services.PSObject.Properties.Name -notcontains $serviceName) {
            throw "Backup field Services.$serviceName is missing."
        }
    }
}

function Assert-BackupSection {
    param($Section, [string]$Name, [hashtable]$Fields, [bool]$Required)
    if ($null -eq $Section -and -not $Required) { return }
    Assert-BackupObject $Section $Name
    foreach ($fieldName in $Fields.Keys) {
        if ($Required -and $Section.PSObject.Properties.Name -notcontains $fieldName) {
            throw "Backup field $Name.$fieldName is missing."
        }
        Assert-BackupValue $Section.$fieldName $Fields[$fieldName] "$Name.$fieldName"
    }
}

function Assert-BackupAutorun {
    param($Autorun, [bool]$Required)
    if ($autorun -is [string] -and -not $Required) { return }
    if ($null -eq $autorun -and -not $Required) { return }
    Assert-BackupObject $autorun 'SecurityHealthAutorun'
    if ($Required -and ($autorun.PSObject.Properties.Name -notcontains 'Value' -or $autorun.PSObject.Properties.Name -notcontains 'Type')) {
        throw 'Backup SecurityHealthAutorun.Value / Type is missing.'
    }
    Assert-BackupValue $autorun.Value 'String' 'SecurityHealthAutorun.Value'
    if ($null -ne $autorun.Type -and $autorun.Type -cnotin @('String', 'ExpandString')) {
        throw 'Invalid SecurityHealthAutorun.Type.'
    }
}

function Read-BackupState {
    [CmdletBinding()]
    param([string]$Path, [switch]$AllowOtherUser)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -eq 0 -or $stream.Length -gt $script:MaximumBackupBytes) {
            throw 'Backup file is empty or exceeds the 1 MiB limit.'
        }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true)
        try { $rawJson = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $backup = ConvertFrom-Json -InputObject $rawJson -ErrorAction Stop
    Assert-BackupState $backup
    if ($backup.PSObject.Properties.Name -notcontains 'SchemaVersion') {
        Write-Warning 'Legacy backup: Windows installation and user identity cannot be verified.'
        return $backup
    }
    Assert-BackupObject $backup.Identity 'Identity'
    $identity = Get-BackupIdentity
    if ($backup.Identity.MachineGuid -isnot [string] -or $backup.Identity.MachineGuid -ne $identity.MachineGuid) {
        throw [InvalidOperationException]::new('Backup belongs to another Windows installation.')
    }
    if ($backup.Identity.UserSid -isnot [string] -or [string]::IsNullOrWhiteSpace($backup.Identity.UserSid)) {
        throw 'Backup user identity is missing or invalid.'
    }
    if (-not $AllowOtherUser -and $backup.Identity.UserSid -ne $identity.UserSid) {
        throw 'Backup belongs to another Windows user.'
    }
    return $backup
}

function Write-BackupState {
    param([string]$Path, [hashtable]$Backup)
    # Move without overwrite preserves the first backup even if another run wins the race.
    $temporaryPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $Backup.SchemaVersion = $script:BackupSchemaVersion
        $Backup.Identity = Get-BackupIdentity
        $json = ConvertTo-Json -InputObject $Backup -Depth 5
        [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($true))
        $null = Read-BackupState $temporaryPath
        [IO.File]::Move($temporaryPath, $Path)
    } finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}
