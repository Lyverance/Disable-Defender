# Preserve owner, primary group and DACL; the scripts never modify the SACL.
$script:MaximumSecurityDescriptorCharacters = 65536
$script:SecuritySections = [System.Security.AccessControl.AccessControlSections]'Access, Owner, Group'

function Get-SecurityRegistryPaths {
    $serviceNames = @('WinDefend', 'WdFilter', 'MDCoreSvc', 'WdBoot', 'WdNisSvc', 'WdNisDrv', 'Sense', 'webthreatdefsvc', 'webthreatdefusersvc', 'wscsvc')
    foreach ($controlSetIndex in 1..3) {
        foreach ($serviceName in $serviceNames) {
            'SYSTEM\ControlSet{0:D3}\Services\{1}' -f $controlSetIndex, $serviceName
        }
    }
}

function Get-SecurityState {
    $registry = @{}
    foreach ($keyPath in (Get-SecurityRegistryPaths)) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath)
        try {
            $registry[$keyPath] = if ($null -eq $key) { $null } else {
                $key.GetAccessControl($script:SecuritySections).GetSecurityDescriptorSddlForm($script:SecuritySections)
            }
        } finally { if ($null -ne $key) { $key.Dispose() } }
    }
    $filePath = Join-Path $env:SystemRoot 'System32\smartscreen.exe'
    $fileDescriptor = if (Test-Path -LiteralPath $filePath) {
        (Get-Acl -LiteralPath $filePath).GetSecurityDescriptorSddlForm($script:SecuritySections)
    } else { $null }
    return @{ Registry = $registry; SmartScreen = $fileDescriptor }
}

function Assert-SecurityDescriptor {
    param($Value)
    if ($null -eq $Value) { return }
    if ($Value -isnot [string] -or $Value.Length -gt $script:MaximumSecurityDescriptorCharacters) { throw 'Invalid security descriptor size or type.' }
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Value)
    if ($null -eq $descriptor.Owner -or $null -eq $descriptor.Group -or
        $null -eq $descriptor.DiscretionaryAcl -or $null -ne $descriptor.SystemAcl) {
        throw 'Security descriptor must contain owner, group and DACL, without SACL.'
    }
}

function Assert-SecurityState {
    param($State)
    Assert-BackupObject $State 'SecurityState'
    Assert-BackupObject $State.Registry 'SecurityState.Registry'
    $paths = @(Get-SecurityRegistryPaths)
    if (@($State.Registry.PSObject.Properties).Count -ne $paths.Count) { throw 'Incomplete registry security snapshot.' }
    foreach ($keyPath in $paths) {
        if ($State.Registry.PSObject.Properties.Name -notcontains $keyPath) { throw "Missing registry security snapshot: $keyPath" }
        Assert-SecurityDescriptor $State.Registry.$keyPath
    }
    if ($State.PSObject.Properties.Name -notcontains 'SmartScreen') { throw 'Missing SmartScreen security snapshot.' }
    Assert-SecurityDescriptor $State.SmartScreen
}

function Restore-RegistrySecurity {
    param([Microsoft.Win32.RegistryKey]$Key, [string]$Descriptor)
    $security = [System.Security.AccessControl.RegistrySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Descriptor, $script:SecuritySections)
    $Key.SetAccessControl($security)
}

function Restore-FileSecurity {
    param([string]$Path, [string]$Descriptor)
    $security = [System.Security.AccessControl.FileSecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Descriptor, $script:SecuritySections)
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
}

# Disabled-state ownership well-known SID: this script takes ownership of
# smartscreen.exe as BUILTIN\Administrators during Disable (observed in a
# real VM cycle; the service registry keys themselves are not actually
# re-owned by the time Disable finishes, so there is nothing comparable to
# check there). $Path defaults to the real file so production code needs no
# argument; tests inject a temporary file instead of the real smartscreen.exe.
$script:AdministratorsSid = 'S-1-5-32-544'
function Get-SmartScreenOwnerSid {
    param([string]$Path = (Join-Path $env:SystemRoot 'System32\smartscreen.exe'))
    try { $null = Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
    $ownerSections = [System.Security.AccessControl.AccessControlSections]::Owner
    $descriptor = (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm($ownerSections)
    return ([System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor)).Owner.Value
}

function Test-SmartScreenExecuteDenied {
    param([string]$Path = (Join-Path $env:SystemRoot 'System32\smartscreen.exe'))
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $execute = [Security.AccessControl.FileSystemRights]::ExecuteFile
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference -eq $usersSid -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
            ($rule.FileSystemRights -band $execute) -eq $execute -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
            return $true
        }
    }
    return $false
}

function Get-ComparableSecurityDescriptor {
    param([string]$Descriptor)
    if ([string]::IsNullOrEmpty($Descriptor)) { return $null }
    $security = [System.Security.AccessControl.RawSecurityDescriptor]::new($Descriptor)
    # Windows may set these bookkeeping bits when applying inherited permissions.
    # Keep DACL protection, ACE inheritance flags, owner, group and every ACE intact.
    $bookkeeping = [System.Security.AccessControl.ControlFlags]'DiscretionaryAclAutoInherited, DiscretionaryAclAutoInheritRequired'
    $security.SetFlags($security.ControlFlags -band (-bnot $bookkeeping))
    return $security.GetSddlForm($script:SecuritySections)
}
