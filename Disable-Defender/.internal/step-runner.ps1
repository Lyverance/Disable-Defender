# step-runner.ps1 -- executes a list of operations and returns one result per
# item, independent of any caller script scope. Callers render the results and
# track aggregate failure state themselves -- see Invoke-StepSafe / Invoke-RegStep
# in stage-normal.ps1 and stage-safe.ps1 for the console adapter.

# Runs PowerShell-cmdlet operations. $Ops = array of @{ Label; Action }.
function Invoke-StepOps {
    param([array]$Ops)
    $results = @()
    foreach ($op in $Ops) {
        try {
            & $op.Action
            $results += [pscustomobject]@{ Label = $op.Label; Ok = $true; Error = $null }
        } catch {
            $results += [pscustomobject]@{ Label = $op.Label; Ok = $false; Error = $_.ToString() }
        }
    }
    return $results
}

# Runs reg.exe operations. $Entries = array of @{ Label; Cmd }.
# Uses *> $null (not | Out-Null) -- piping through Out-Null resets $LASTEXITCODE to 0 in PS 5.1.
function Invoke-RegStepOps {
    param([array]$Entries)
    $results = @()
    foreach ($entry in $Entries) {
        & $entry.Cmd *> $null
        if ($LASTEXITCODE -eq 0) {
            $results += [pscustomobject]@{ Label = $entry.Label; Ok = $true; Error = $null }
        } else {
            $results += [pscustomobject]@{ Label = $entry.Label; Ok = $false; Error = "reg.exe exit $LASTEXITCODE" }
        }
    }
    return $results
}

# Renders a cmdlet step and records a partial result for the calling stage.
function Invoke-StepSafe {
    param([string]$Header, [array]$Ops, [string]$PartialNote)
    Write-StepStart $Header
    $stepResults = Invoke-StepOps $Ops
    if (Write-StepResult $stepResults $PartialNote) {
        $script:HasErrors = $true
    }
}
