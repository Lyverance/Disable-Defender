# Helpers

function Check($label, $ok) {
    $script:SectionItems += [pscustomobject]@{ Label = $label; Ok = [bool]$ok; Info = $false }
    if ($ok) { $script:PassCount++ } else { $script:FailCount++ }
}

# CheckOK: item that is informational / always correct -- NOT counted in $PassCount.
# $PassCount is only incremented by Check() on a true verified success;
# informational items (skipped, n/a, already-correct) don't inflate the pass ratio.
function CheckOK($label) {
    $script:SectionItems += [pscustomobject]@{ Label = $label; Ok = $true; Info = $true }
    # Intentionally NOT incrementing $script:PassCount -- this is informational, not a verified check.
}

# Flushes the items buffered by Check()/CheckOK() since the last Write-Section
# call as a single line for the whole section: "[Title] OK (n/n)" in green on
# a full match, or "[Title] PARTIAL (n/n)" in yellow with one [+]/[~] line per
# item -- matching the disable/restore step rendering (Write-StepResult in
# console-ui.ps1) word-for-word, not just the color -- when anything differs.
function Write-Section {
    param([string]$Title)
    $items = $script:SectionItems
    $script:SectionItems = @()
    $verifiedCount = @($items | Where-Object { -not $_.Info }).Count
    $failedItems   = @($items | Where-Object { -not $_.Ok })

    if ($failedItems.Count -eq 0) {
        $suffix = if ($verifiedCount -gt 0) { " ($verifiedCount/$verifiedCount)" } else { '' }
        Write-Host "  [$Title] OK$suffix" -ForegroundColor Green
    } else {
        Write-Host "  [$Title] PARTIAL ($($verifiedCount - $failedItems.Count)/$verifiedCount)" -ForegroundColor Yellow
        foreach ($item in $items) {
            if ($item.Ok) {
                Write-Host "    [+] $($item.Label)" -ForegroundColor Green
            } else {
                Write-Host "    [~] $($item.Label)" -ForegroundColor Red
            }
        }
    }
}

