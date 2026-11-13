<#
  safe-mode-entry.ps1
  A one-shot boot entry for the Safe Mode step.

  Setting "safeboot" on the running entry would keep every later boot in Safe
  Mode until something cleared it, so a person who cannot sign in there (a PIN
  or Windows Hello does not work in Safe Mode, only the account password) would
  be stuck. Instead Disable copies the running entry, sets "safeboot" on the
  copy only, and boots the copy once with "bcdedit /bootsequence". The real
  entry is never touched: a boot that does not reach the Safe Mode step, or a
  restart from the sign-in screen, lands in normal Windows.

  The copy carries a fixed description so it can be found again without keeping
  its identifier anywhere; bcdedit prints its field names in the Windows display
  language, so the entry is matched by that description and by the identifier
  pattern, never by a field name.
#>

$script:SafeModeEntryDescription = 'Disable-Defender Safe Mode (temporary)'
$script:BootEntryIdPattern = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'

# Identifiers of every boot entry carrying our description. An entry's section is
# a title, a line of dashes, then its identifier line; every later identifier in
# the section (recoverysequence, resumeobject) refers to another entry and is not
# ours. /v makes bcdedit print the real identifier of the running entry instead
# of {current}, which is how the copy appears once Safe Mode has booted it.
function Get-SafeModeEntryId {
    $listing = bcdedit /enum all /v 2>&1
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /enum all /v failed (exit $LASTEXITCODE)" }
    $sections = (($listing | ForEach-Object { "$_" }) -join "`n") -split "(?:\r?\n){2,}"
    foreach ($section in $sections) {
        if (-not $section.Contains($script:SafeModeEntryDescription)) { continue }
        $lines = @($section -split "\r?\n")
        $dashesAt = 0
        while ($dashesAt -lt $lines.Count -and $lines[$dashesAt] -notmatch '^-{3,}\s*$') { $dashesAt++ }
        if ($dashesAt + 1 -ge $lines.Count) { continue }
        $match = [regex]::Match($lines[$dashesAt + 1], $script:BootEntryIdPattern)
        if ($match.Success) { $match.Value }
    }
}

# Creates the entry, marks it Safe Mode, hides it from the boot menu and
# selects it for the next boot only. On any failure the half-made entry is
# removed and the call throws. Returns the identifier.
function New-SafeModeBootEntry {
    # A leftover from an earlier interrupted run must not pile up.
    Remove-SafeModeBootEntry

    $copyOutput = bcdedit /copy '{current}' /d $script:SafeModeEntryDescription 2>&1
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /copy failed: $copyOutput" }
    $match = [regex]::Match("$copyOutput", $script:BootEntryIdPattern)
    if (-not $match.Success) { throw "bcdedit /copy did not report the new entry: $copyOutput" }
    $entryId = $match.Value

    try {
        $output = bcdedit /set $entryId safeboot minimal 2>&1
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /set safeboot failed: $output" }
        # A copy joins the boot menu; hidden, it never shows a menu on a later
        # boot and bootsequence still selects it.
        $output = bcdedit /displayorder $entryId /remove 2>&1
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /displayorder failed: $output" }
        $output = bcdedit /bootsequence $entryId 2>&1
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /bootsequence failed: $output" }
    } catch {
        bcdedit /delete $entryId *> $null
        throw
    }
    return $entryId
}

# Removes our entry (and the one-time selection pointing at it) when present.
# Safe to call from Safe Mode itself, from normal mode, and when nothing is
# there. Deletes only entries carrying our description.
function Remove-SafeModeBootEntry {
    $ids = @(Get-SafeModeEntryId)
    foreach ($entryId in $ids) {
        # Cancel a selection that has not been used yet, before its target is gone;
        # a selection pointing anywhere else is not ours to cancel.
        $bootManager = bcdedit /enum '{bootmgr}' /v 2>&1 | Out-String
        if ($bootManager.Contains($entryId)) { bcdedit /deletevalue '{bootmgr}' bootsequence *> $null }
        bcdedit /delete $entryId *> $null
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /delete $entryId failed (exit $LASTEXITCODE)" }
    }
}
