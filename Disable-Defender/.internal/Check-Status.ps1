# Check-Status.ps1 — Defender state verification (works both ways)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$pass = 0
$fail = 0

# ok=$true  means "this is the expected/good state"
function Check($label, $ok) {
    if ($ok) {
        Write-Host ("  [OK]   " + $label) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ("  [DIFF] " + $label) -ForegroundColor Red
        $script:fail++
    }
}

function RegAbsent($path, $name) {
    try { $null = (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name; return $false }
    catch { return $true }
}

function RegValue($path, $name, $expected) {
    try { return ((Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name -eq $expected) }
    catch { return $false }
}

function KeyAbsent($subkey) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkey)
        if ($k -eq $null) { return $true }
        $k.Close(); return $false
    } catch { return $true }
}

function ServiceDisabled($name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -eq $null) { return $true }
    return ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped')
}

function TaskDisabled($path, $name) {
    $t = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
    if ($t -eq $null) { return $true }
    return ($t.State -eq 'Disabled')
}

# ── Auto-detect mode ────────────────────────────────────────────────
# If WinDefend service is disabled → defender is OFF → show disable-check
# Otherwise → defender is ON → show restore-check
$defenderOff = ServiceDisabled "WinDefend"

Write-Host ""
if ($defenderOff) {
    Write-Host "  Defender Status: DISABLED" -ForegroundColor Cyan
    Write-Host "  Showing: disable verification (green = applied correctly)" -ForegroundColor DarkGray
} else {
    Write-Host "  Defender Status: ENABLED" -ForegroundColor Cyan
    Write-Host "  Showing: restore verification (green = restored correctly)" -ForegroundColor DarkGray
}
Write-Host "  ==================================" -ForegroundColor Cyan
Write-Host ""

# ── Services ────────────────────────────────────────────────────────
Write-Host "  [Services]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "WinDefend           - Stopped / Disabled"  (ServiceDisabled "WinDefend")
    Check "WdFilter            - Stopped / Disabled"  (ServiceDisabled "WdFilter")
    Check "WdNisSvc            - Stopped / Disabled"  (ServiceDisabled "WdNisSvc")
    Check "WdNisDrv            - Stopped / Disabled"  (ServiceDisabled "WdNisDrv")
    Check "Sense               - Stopped / Disabled"  (ServiceDisabled "Sense")
    Check "webthreatdefsvc     - Stopped / Disabled"  (ServiceDisabled "webthreatdefsvc")
    Check "webthreatdefusersvc - Stopped / Disabled"  (ServiceDisabled "webthreatdefusersvc")
    Check "wscsvc              - Stopped / Disabled"  (ServiceDisabled "wscsvc")
} else {
    Check "WinDefend           - Running"  (-not (ServiceDisabled "WinDefend"))
    Check "WdFilter            - Running"  (-not (ServiceDisabled "WdFilter"))
    Check "WdNisSvc            - Running"  (-not (ServiceDisabled "WdNisSvc"))
    Check "WdNisDrv            - Running"  (-not (ServiceDisabled "WdNisDrv"))
    Check "Sense               - Running"  (-not (ServiceDisabled "Sense"))
    Check "webthreatdefsvc     - Running"  (-not (ServiceDisabled "webthreatdefsvc"))
    Check "webthreatdefusersvc - Running"  (-not (ServiceDisabled "webthreatdefusersvc"))
    Check "wscsvc              - Running"  (-not (ServiceDisabled "wscsvc"))
}
Write-Host ""

# ── Scheduled Tasks ─────────────────────────────────────────────────
Write-Host "  [Scheduled Tasks]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "Cache Maintenance      - Disabled" (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Cache Maintenance")
    Check "Cleanup                - Disabled" (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Cleanup")
    Check "Scheduled Scan        - Disabled" (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Scheduled Scan")
    Check "Verification          - Disabled" (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Verification")
    Check "RecoverabilityToast   - Disabled" (TaskDisabled "\Microsoft\Windows\AccountHealth\" "RecoverabilityToastTask")
} else {
    Check "Cache Maintenance      - Enabled" (-not (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Cache Maintenance"))
    Check "Cleanup                - Enabled" (-not (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Cleanup"))
    Check "Scheduled Scan        - Enabled" (-not (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Scheduled Scan"))
    Check "Verification          - Enabled" (-not (TaskDisabled "\Microsoft\Windows\Windows Defender\" "Windows Defender Verification"))
    Check "RecoverabilityToast   - Enabled" (-not (TaskDisabled "\Microsoft\Windows\AccountHealth\" "RecoverabilityToastTask"))
}
Write-Host ""

# ── EPP Context Menu ────────────────────────────────────────────────
$eppSubkeys = @(
    'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
)
$eppLabels = @('Classes\*\...EPP', 'Classes\Drive\...EPP', 'Classes\Directory\...EPP', 'Classes\Dir\Bg\...EPP', 'Classes\Folder\...EPP')

if ($defenderOff) {
    Write-Host "  [EPP Context Menu - absent = OK]" -ForegroundColor Yellow
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        Check ($eppLabels[$i] + " - removed") (KeyAbsent $eppSubkeys[$i])
    }
} else {
    Write-Host "  [EPP Context Menu - present = OK]" -ForegroundColor Yellow
    for ($i = 0; $i -lt $eppSubkeys.Count; $i++) {
        Check ($eppLabels[$i] + " - present") (-not (KeyAbsent $eppSubkeys[$i]))
    }
}
Write-Host ""

# ── Security Center Notifications ───────────────────────────────────
Write-Host "  [Security Center Notifications]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "AntiVirusDisableNotify = 1"          (RegValue  'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify' 1)
    Check "AntiVirusOverride = 1"               (RegValue  'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride' 1)
    Check "SecurityAndMaintenance toast Off"    (RegValue  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled' 0)
} else {
    Check "AntiVirusDisableNotify - absent"     (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusDisableNotify')
    Check "AntiVirusOverride - absent"          (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Security Center' 'AntiVirusOverride')
    Check "SecurityAndMaintenance toast - absent" (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' 'Enabled')
}
Write-Host ""

# ── SmartScreen ─────────────────────────────────────────────────────
Write-Host "  [SmartScreen]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "EnableSmartScreen = 0"    (RegValue  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 0)
    Check "SmartScreenEnabled = Off" (RegValue  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off')
} else {
    Check "EnableSmartScreen - absent"    (RegAbsent 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
    Check "SmartScreenEnabled - absent"   (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
}
Write-Host ""

# ── Tray / Health Center ────────────────────────────────────────────
Write-Host "  [Tray / Health Center]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "HideSystray = 1"         (RegValue  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray' 1)
    Check "DisableHealthCenter = 1" (RegValue  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HealthCenter' 'DisableHealthCenter' 1)
} else {
    Check "HideSystray - absent"         (RegAbsent 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' 'HideSystray')
    Check "DisableHealthCenter - absent" (RegAbsent 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HealthCenter' 'DisableHealthCenter')
}
Write-Host ""

# ── Autostart ───────────────────────────────────────────────────────
Write-Host "  [Autostart]" -ForegroundColor Yellow
if ($defenderOff) {
    Check "SecurityHealth - removed from Run" (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth')
} else {
    Check "SecurityHealth - present in Run"  (-not (RegAbsent 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'SecurityHealth'))
}
Write-Host ""

# ── Summary ─────────────────────────────────────────────────────────
Write-Host "  ======================================" -ForegroundColor Cyan
$total = $pass + $fail
if ($fail -eq 0) {
    Write-Host ("  ALL OK: " + $pass + "/" + $total) -ForegroundColor Green
} else {
    Write-Host ("  OK: " + $pass + "/" + $total + "   DIFF: " + $fail) -ForegroundColor Yellow
    if ($defenderOff) {
        Write-Host "  Items marked [DIFF] were not applied or were reverted." -ForegroundColor Red
    } else {
        Write-Host "  Items marked [DIFF] were not fully restored." -ForegroundColor Red
    }
}
Write-Host ""
Write-Host "  Note: WdBoot (boot-start driver) is not checked here -" -ForegroundColor DarkGray
Write-Host "  Secure Boot + TPM may reset it to Start=0, which is normal." -ForegroundColor DarkGray
Write-Host ""
pause
