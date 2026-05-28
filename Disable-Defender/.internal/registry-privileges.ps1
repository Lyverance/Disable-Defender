param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('take','restore')]
    [string]$Action
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$sig = @'
[DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern bool LookupPrivilegeValue(string SystemName, string Name, ref long Luid);
[DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAll, ref LUID_AND_ATTRIBUTES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
[StructLayout(LayoutKind.Sequential, Pack=1)]
public struct LUID_AND_ATTRIBUTES { public int Count; public long Luid; public int Attributes; }
public static void EnablePrivilege(string name) {
    IntPtr token = IntPtr.Zero;
    OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, ref token);
    LUID_AND_ATTRIBUTES la = new LUID_AND_ATTRIBUTES();
    la.Count = 1; la.Attributes = 2;
    LookupPrivilegeValue(null, name, ref la.Luid);
    AdjustTokenPrivileges(token, false, ref la, 0, IntPtr.Zero, IntPtr.Zero);
}
'@

Add-Type -MemberDefinition $sig -Name "Privs" -Namespace "TokenUtil" -PassThru | Out-Null
[TokenUtil.Privs]::EnablePrivilege("SeTakeOwnershipPrivilege")
[TokenUtil.Privs]::EnablePrivilege("SeRestorePrivilege")

$sidAdmins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$sidSystem  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")

# PPL-protected keys: SetAccessControl may fail in normal mode — treated as warning, not fatal
$pplKeys = @(
    'SYSTEM\CurrentControlSet\Services\WinDefend',
    'SYSTEM\CurrentControlSet\Services\WdFilter',
    'SYSTEM\CurrentControlSet\Services\WdBoot',
    'SYSTEM\CurrentControlSet\Services\WdNisSvc',
    'SYSTEM\CurrentControlSet\Services\WdNisDrv'
)

# Non-PPL keys: failure here is fatal
$normalKeys = @(
    'SYSTEM\CurrentControlSet\Services\Sense',
    'SYSTEM\CurrentControlSet\Services\webthreatdefsvc',
    'SYSTEM\CurrentControlSet\Services\webthreatdefusersvc',
    'SYSTEM\CurrentControlSet\Services\wscsvc'
)

$fatalFailed = $false

function Set-KeyOwnership($subkey, $warn) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subkey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        if ($k -eq $null) { throw "OpenSubKey(TakeOwnership) returned null" }

        $acl = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)

        if ($Action -eq 'take') {
            $acl.SetOwner($sidAdmins)
        } else {
            $acl.SetOwner($sidSystem)
        }
        $k.SetAccessControl($acl)
        $k.Close()

        if ($Action -eq 'take') {
            $k2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subkey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            if ($k2 -eq $null) { throw "OpenSubKey(ChangePermissions) returned null" }

            $acl2 = $k2.GetAccessControl()
            $rule  = New-Object System.Security.AccessControl.RegistryAccessRule(
                $sidAdmins,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl2.SetAccessRule($rule)
            $k2.SetAccessControl($acl2)
            $k2.Close()
        }

        Write-Host ("    OK: " + $subkey) -ForegroundColor Green

    } catch {
        if ($warn) {
            Write-Host ("    WARN (PPL): " + $subkey) -ForegroundColor Yellow
        } else {
            Write-Host ("    FAIL: " + $subkey + " - " + $_.Exception.Message) -ForegroundColor Red
            $script:fatalFailed = $true
        }
    }
}

foreach ($subkey in $pplKeys)    { Set-KeyOwnership $subkey $true  }
foreach ($subkey in $normalKeys) { Set-KeyOwnership $subkey $false }

if ($fatalFailed) { exit 1 } else { exit 0 }
