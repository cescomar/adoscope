function Resolve-AdoScopeBaseline {
    <#
    .SYNOPSIS
        Marks findings already present in a previous adoscope JSON report (matched by
        Fingerprint) with InBaseline = $true and returns a summary:
          New         findings not in the baseline (what a CI gate should block)
          Existing    findings already in the baseline (accepted debt)
          Resolved    baseline findings gone although the run could have seen them: the check
                      is Evaluated now, its project is in scope and its parameters are unchanged
          Unverified  baseline findings gone without that proof (check NotEvaluated, Partial,
                      Error or disabled; project out of scope; parameters changed). Never
                      counted as fixed: a 403 or a narrower scope is not a remediation.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report,
        [Parameter(Mandatory)][string]$Path
    )

    $previous = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    if ($previous -isnot [hashtable] -or $previous['Tool'] -ne 'adoscope' -or -not $previous.ContainsKey('Findings')) {
        throw "Baseline '$Path' is not an adoscope JSON report (create one with -JsonPath)."
    }
    # A baseline of another organization would silently turn every finding into "new".
    if ($previous['Organization'] -ne $Report.Organization) {
        throw "Baseline '$Path' belongs to organization '$($previous['Organization'])', not '$($Report.Organization)'."
    }

    $known = @{}
    foreach ($old in @($previous.Findings)) { if ($old -is [hashtable] -and $old['Fingerprint']) { $known[$old.Fingerprint] = $old } }
    $current = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($f in @($Report.Findings)) {
        $null = $current.Add($f.Fingerprint)
        $f.InBaseline = $known.ContainsKey($f.Fingerprint)
    }
    $status = @{}; foreach ($c in @($Report.Checks)) { $status[$c.CheckId] = $c.Status }
    $now = @{}; foreach ($r in @($Report.Rules)) { $now[$r.Id] = ConvertTo-AdoScopeComparable $r.Parameters }
    $then = @{}; foreach ($r in @($previous['Rules'])) { if ($r -is [hashtable]) { $then[$r['Id']] = ConvertTo-AdoScopeComparable $r['Parameters'] } }

    $resolved = 0; $unverified = 0
    foreach ($old in $known.Values | Where-Object { -not $current.Contains($_.Fingerprint) }) {
        $id = $old['CheckId']
        $proven = $status[$id] -eq 'Evaluated' -and (-not $old['Project'] -or $old['Project'] -in $Report.Scope.Projects) -and
            $then.ContainsKey($id) -and $then[$id] -eq $now[$id]
        if ($proven) { $resolved++ } else { $unverified++ }
    }
    [pscustomobject]@{
        Path       = $Path
        New        = @($Report.Findings | Where-Object { -not $_.InBaseline }).Count
        Existing   = @($Report.Findings | Where-Object InBaseline).Count
        Resolved   = $resolved
        Unverified = $unverified
    }
}

function ConvertTo-AdoScopeComparable {
    <# Canonical JSON of a parameter table (keys sorted at every level), so a value read back from a report compares equal to the live one. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    $sort = {
        param($v)
        if ($v -is [System.Collections.IDictionary]) {
            $o = [ordered]@{}; foreach ($k in $v.Keys | Sort-Object) { $o[[string]$k] = & $sort $v[$k] }; $o
        }
        elseif ($v -is [array]) { , @($v | ForEach-Object { & $sort $_ }) }
        else { $v }
    }
    ConvertTo-Json -InputObject (& $sort $Value) -Depth 20 -Compress
}
