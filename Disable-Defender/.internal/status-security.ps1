. (Join-Path $PSScriptRoot 'restore-verification.ps1')

function Write-RestoredSecurityStatus {
    param($Backup)
    if (-not $Backup -or $Backup.SchemaVersion -lt 4) {
        Write-WarningLine 'Original owner, group and DACL cannot be verified: no v4 backup is available.'
        return
    }
    try {
        Assert-RestoredSecurity $Backup
        Check 'Owner, group and DACL match the backup' $true
    } catch {
        Check ('Owner, group and DACL cannot be verified: ' + $_.Exception.Message) $false
    }
    Write-Section 'Restored security'
}
