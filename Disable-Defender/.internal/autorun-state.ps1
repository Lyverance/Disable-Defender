# SecurityHealth keeps the Windows Security tray icon alive; its Run value is
# removed in both stages. A failed read must stay a failure: treating it as
# "already absent" would leave the autorun in place while the step reports success.

$script:RunKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

function Remove-SecurityHealthAutorun {
    param([string]$RunKeyPath = $script:RunKeyPath)

    $runKey = try { Get-Item -LiteralPath $RunKeyPath -ErrorAction Stop } catch [System.Management.Automation.ItemNotFoundException] { $null }
    if ($null -eq $runKey) { return }
    try {
        $isPresent = $null -ne $runKey.GetValue('SecurityHealth', $null)
    } finally { $runKey.Dispose() }
    if ($isPresent) {
        Remove-ItemProperty -LiteralPath $RunKeyPath -Name 'SecurityHealth' -Force -ErrorAction Stop
    }
}
