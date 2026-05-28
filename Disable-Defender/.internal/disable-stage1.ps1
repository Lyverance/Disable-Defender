<#
  disable-stage1.ps1
  Run in NORMAL mode as Administrator (via 1-Normal-Mode.bat).
  Make sure Tamper Protection is disabled before running (step 1.0 in the guide).
  The script will reboot into Safe Mode at the end.
#>

$ErrorActionPreference = 'SilentlyContinue'

Write-Host ""
Write-Host "=== Step 1 of 2: Normal Mode ===" -ForegroundColor Cyan
Write-Host ""

# ── Scheduled tasks ────────────────────────────────────────────────
Write-Host "[1/5] Disabling Defender scheduled tasks..." -ForegroundColor Yellow

Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Cache Maintenance"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Cleanup"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Scheduled Scan"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Verification"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AccountHealth\"    -TaskName "RecoverabilityToastTask"

Write-Host "    OK" -ForegroundColor Green

# ── EPP context menu ───────────────────────────────────────────────
Write-Host "[2/5] Removing EPP from context menu..." -ForegroundColor Yellow

# FIX: используем .NET Registry напрямую — не зависает на * и надёжно удаляет ключи
$eppKeys = @(
    'SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\EPP',
    'SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\EPP'
)
foreach ($k in $eppKeys) {
    try {
        $parent = $k.Substring(0, $k.LastIndexOf('\'))
        $child  = $k.Substring($k.LastIndexOf('\') + 1)
        $pk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parent, $true)
        if ($pk -ne $null) { $pk.DeleteSubKeyTree($child, $false); $pk.Close() }
    } catch {}
}

Write-Host "    OK" -ForegroundColor Green

# ── Security Center notifications ─────────────────────────────────
Write-Host "[3/5] Disabling Security Center notifications..." -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v AntiVirusOverride       /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f | Out-Null

Write-Host "    OK" -ForegroundColor Green

# ── SmartScreen ────────────────────────────────────────────────────
Write-Host "[4/5] Disabling SmartScreen..." -ForegroundColor Yellow

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"         /v EnableSmartScreen  /t REG_DWORD /d 0   /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ    /d Off /f | Out-Null

Write-Host "    OK" -ForegroundColor Green

# ── SecurityHealth autostart ───────────────────────────────────────
Write-Host "[5/5] Removing SecurityHealth from autostart..." -ForegroundColor Yellow

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"

Write-Host "    OK" -ForegroundColor Green

# ── Reboot into Safe Mode ──────────────────────────────────────────
Write-Host ""
Write-Host "All tasks complete." -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEP:" -ForegroundColor Cyan
Write-Host "  After reboot into Safe Mode, run 2-Safe-Mode.cmd" -ForegroundColor White
Write-Host "  (as Administrator, in Safe Mode)" -ForegroundColor Gray
Write-Host ""
Write-Host "Save all open files." -ForegroundColor Yellow
Write-Host "Press any key to reboot into Safe Mode..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# FIX: одинарные кавычки вокруг {current} в PS передают литерал '{current}' в bcdedit.
# Двойные кавычки безопасны — {current} не содержит PS-переменных.
bcdedit /set "{current}" safeboot minimal | Out-Null
Restart-Computer -Force
