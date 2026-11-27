function Resolve-AdoScopeBaseline {
    <#
    .SYNOPSIS
        Marks findings already present in a previous adoscope JSON report (matched by
        Fingerprint) with InBaseline = $true and returns a summary:
          New       findings not in the baseline (what a CI gate should block)
          Existing  findings already in the baseline (accepted debt)
          Resolved  baseline findings that no longer occur (fixed since then)
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Organization
    )

    $previous = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    if ($previous -isnot [hashtable] -or $previous['Tool'] -ne 'adoscope' -or -not $previous.ContainsKey('Findings')) {
        throw "Baseline '$Path' is not an adoscope JSON report (create one with -JsonPath)."
    }
    # A baseline of another organization would silently turn every finding into "new".
    if ($previous['Organization'] -ne $Organization) {
        throw "Baseline '$Path' belongs to organization '$($previous['Organization'])', not '$Organization'."
    }

    $known = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($old in @($previous.Findings)) { if ($old -is [hashtable] -and $old['Fingerprint']) { $null = $known.Add($old.Fingerprint) } }
    $current = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in $Finding) {
        $null = $current.Add($f.Fingerprint)
        $f.InBaseline = $known.Contains($f.Fingerprint)
    }
    [pscustomobject]@{
        Path     = $Path
        New      = @($Finding | Where-Object { -not $_.InBaseline }).Count
        Existing = @($Finding | Where-Object InBaseline).Count
        Resolved = @($known | Where-Object { -not $current.Contains($_) }).Count
    }
}
