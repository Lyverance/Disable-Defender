param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('take','restore','restore-file')]
    [string]$Action,
    [switch]$UseDefaults
)

$ErrorActionPreference = 'Stop'
if ($UseDefaults -and $Action -ne 'restore') { throw 'UseDefaults is only valid for registry restoration.' }

$cSharpCode = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class PrivilegeHelper {
    private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const int TOKEN_QUERY             = 0x0008;
    private const int SE_PRIVILEGE_ENABLED    = 0x0002;
    private const int ERROR_NOT_ALL_ASSIGNED  = 1300;

    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, int desiredAccess, ref IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool LookupPrivilegeValue(string systemName, string privilegeName, ref LUID luid);

    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    // LUID layout: two separate fields matching the actual Win32 struct (LowPart=ULONG, HighPart=LONG).
    // A single 'long' field or Pack=1 breaks ARM64 alignment -- LUID must be 8-byte-aligned per Win32 ABI.
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID {
        public uint LowPart;
        public int  HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES {
        public int  PrivilegeCount;
        public LUID Luid;
        public int  Attributes;
    }

    public static void Enable(string privilegeName) {
        // tokenHandle is guaranteed to be closed in the finally block even if
        // LookupPrivilegeValue or AdjustTokenPrivileges throws -- a leaked
        // TOKEN_ADJUST_PRIVILEGES handle is a detectable IOC for EDR tools.
        IntPtr tokenHandle = IntPtr.Zero;
        try {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref tokenHandle))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "OpenProcessToken failed for privilege: " + privilegeName);

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Attributes     = SE_PRIVILEGE_ENABLED;

            if (!LookupPrivilegeValue(null, privilegeName, ref tp.Luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "LookupPrivilegeValue failed for privilege: " + privilegeName);

            // AdjustTokenPrivileges returns true even on partial success --
            // check GetLastError for ERROR_NOT_ALL_ASSIGNED (1300) explicitly.
            AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int lastErr = Marshal.GetLastWin32Error();
            if (lastErr == ERROR_NOT_ALL_ASSIGNED)
                throw new Win32Exception(lastErr,
                    "AdjustTokenPrivileges: privilege not held by process token: " + privilegeName);
            if (lastErr != 0)
                throw new Win32Exception(lastErr,
                    "AdjustTokenPrivileges failed for privilege: " + privilegeName);
        } finally {
            if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $cSharpCode -Language CSharp
} catch {
    exit 2
}

try {
    [PrivilegeHelper]::Enable('SeTakeOwnershipPrivilege')
    [PrivilegeHelper]::Enable('SeRestorePrivilege')
} catch {
    exit 2
}

$securityBackup = $null
if (-not $UseDefaults) {
    . (Join-Path $PSScriptRoot 'backup-state.ps1')
    $backupPath = Join-Path $PSScriptRoot 'defender-backup.json'
    if (Test-Path -LiteralPath $backupPath) {
        try { $securityBackup = Read-BackupState $backupPath -AllowOtherUser } catch { Write-Error $_; exit 1 }
    }
}
if ($Action -eq 'restore-file') {
    try {
        if ($null -eq $securityBackup -or $securityBackup.SchemaVersion -lt 4) { throw 'No exact file security snapshot available.' }
        $descriptor = $securityBackup.SecurityState.SmartScreen
        if ($null -ne $descriptor) {
            Restore-FileSecurity (Join-Path $env:SystemRoot 'System32\smartscreen.exe') $descriptor
        } elseif (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\smartscreen.exe')) {
            throw 'SmartScreen appeared after the backup; its original security is unknown.'
        }
        exit 0
    } catch { Write-Error $_; exit 1 }
}

$sidAdmins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$sidSystem  = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')

# Every service this tool ever writes a Start value for, on either path:
# stage-safe.ps1's active disable list (excluding wscsvc)
# and restore-from-backup.ps1's $defenderServiceNames, which still restores
# wscsvc for backups an older version of this tool made while it did disable
# it. Ownership must be taken here for both, so this list stays the union of
# the two, not just a mirror of stage-safe.ps1's.
$serviceNames = @(
    'WinDefend'
    'WdFilter'
    'MDCoreSvc'
    'WdBoot'
    'WdNisSvc'
    'WdNisDrv'
    'Sense'
    'webthreatdefsvc'
    'webthreatdefusersvc'
    'wscsvc'              # Windows Security Center -- kept for restoring older backups, see above
)

# Target ALL concrete ControlSets (001, 002, etc.) plus the alias.
# CurrentControlSet is just an alias -- on normal boot Windows may load
# ControlSet001 or ControlSet002 directly, discarding alias changes.
# Each probe handle is closed immediately after the existence check;
# open raw handles to SYSTEM\ControlSet* are a known EDR detection pattern
# (CrowdStrike, Carbon Black).
$controlSets = [System.Collections.Generic.List[string]]@('CurrentControlSet')
foreach ($controlSetIndex in 1..3) {
    $csName          = 'ControlSet{0:D3}' -f $controlSetIndex
    $controlSetProbe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\$csName")
    if ($null -ne $controlSetProbe) {
        $controlSetProbe.Close()
        $controlSets.Add($csName)
    }
}

$allKeyPaths = [System.Collections.Generic.List[string]]@()
foreach ($csName in $controlSets) {
    foreach ($svcName in $serviceNames) { $allKeyPaths.Add("SYSTEM\$csName\Services\$svcName") }
}

$targetOwner = if ($Action -eq 'take') { $sidAdmins } else { $sidSystem }
$anyFailed   = $false

foreach ($subkeyPath in $allKeyPaths) {
    $ownershipKey   = $null
    $permissionsKey = $null
    try {
        if ($null -ne $securityBackup -and $securityBackup.SchemaVersion -ge 4) {
            # CurrentControlSet may resolve to a different concrete set after reboot.
            $concretePath = $subkeyPath
            if ($subkeyPath.StartsWith('SYSTEM\CurrentControlSet\')) {
                $current = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Select' -Name Current -ErrorAction Stop).Current
                $concretePath = $subkeyPath.Replace('CurrentControlSet', ('ControlSet{0:D3}' -f $current))
            }
            $descriptor = $securityBackup.SecurityState.Registry.$concretePath
            if ($null -eq $descriptor) {
                # Absent when the backup was taken, present now: installed later (a Windows
                # or platform update). Neither Disable nor Restore touches it, so there is
                # nothing to roll back and no original state to return it to.
                $probe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath)
                if ($null -eq $probe) { continue }
                $probe.Dispose()
                Write-Warning "${subkeyPath}: installed after the backup, left as found."
                continue
            }
        }
        if ($Action -eq 'restore' -and $null -ne $securityBackup -and $securityBackup.SchemaVersion -ge 4) {
            # The alias and its concrete ControlSet address the same key. Once the
            # original ACL is back, it may intentionally deny another WRITE_DAC open.
            $probe = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath)
            if ($null -eq $probe) { throw "Registry key disappeared: $subkeyPath" }
            try {
                $currentDescriptor = $probe.GetAccessControl($script:SecuritySections).GetSecurityDescriptorSddlForm($script:SecuritySections)
            } finally { $probe.Dispose() }
            if ((Get-ComparableSecurityDescriptor $currentDescriptor) -ceq (Get-ComparableSecurityDescriptor $descriptor)) { continue }
            $permissionsKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subkeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]'ChangePermissions, TakeOwnership')
            if ($null -eq $permissionsKey) { throw "Registry key disappeared: $subkeyPath" }
            Restore-RegistrySecurity $permissionsKey $descriptor
            continue
        }
        $ownershipKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subkeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        if ($null -eq $ownershipKey) { continue }  # key absent in this ControlSet -- not an error

        $ownerAcl = $ownershipKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
        $ownerAcl.SetOwner($targetOwner)
        $ownershipKey.SetAccessControl($ownerAcl)

        if ($Action -eq 'take') {
            $permissionsKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $subkeyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions
            )
            if ($null -eq $permissionsKey) { throw 'OpenSubKey(ChangePermissions) returned null' }

            $permissionsAcl   = $permissionsKey.GetAccessControl()
            $fullControlRule  = [System.Security.AccessControl.RegistryAccessRule]::new(
                $sidAdmins,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $permissionsAcl.SetAccessRule($fullControlRule)
            $permissionsKey.SetAccessControl($permissionsAcl)
        }
    } catch {
        Write-Warning "${subkeyPath}: $_"
        $anyFailed = $true
    } finally {
        if ($null -ne $permissionsKey) { $permissionsKey.Close() }
        if ($null -ne $ownershipKey)   { $ownershipKey.Close()   }
    }
}

if ($anyFailed) { exit 1 } else { exit 0 }
