function Invoke-AdoScopeCheck {
    <#
    .SYNOPSIS
        Runs checks against a context. Returns one status per check and all findings.

    .DESCRIPTION
        Check status:
          Evaluated    - all required collections Ok.
          Partial      - ran, but at least one required collection is Partial.
          NotEvaluated - a required collection is missing, Failed or Forbidden, or a parameter
                         listed in RequiredParameters is empty (the check could find nothing).
                         Never reported as "clean": zero findings would be a lie.
          Error        - the check threw or emitted something that is not a finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable[]]$Check,
        [Parameter(Mandatory)][hashtable]$Context,
        # Per-check parameter overrides: @{ HYG001 = @{ days = 30 } }
        [hashtable]$Parameters = @{}
    )

    $statuses = [System.Collections.Generic.List[object]]::new()
    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($c in $Check) {
        $effective = $c.Parameters.Clone()
        if ($Parameters[$c.Id] -is [hashtable]) {
            foreach ($key in $Parameters[$c.Id].Keys) { $effective[$key] = $Parameters[$c.Id][$key] }
        }
        $state = Get-AdoScopeCheckReadiness -Check $c -Context $Context -Parameters $effective
        if ($state.Status -eq 'NotEvaluated') {
            $statuses.Add([pscustomobject]@{ CheckId = $c.Id; Status = $state.Status; Message = $state.Message })
            continue
        }

        try {
            $output = @(& $c.Test $Context $effective)
            $bad = @($output | Where-Object { $_.PSObject.TypeNames -notcontains 'AdoScope.Finding' })
            if ($bad) { throw "Test emitted $($bad.Count) object(s) that are not findings; use New-AdoScopeFinding." }
            foreach ($finding in $output) { $findings.Add((Complete-AdoScopeFinding -Finding $finding -Check $c)) }
            $statuses.Add([pscustomobject]@{ CheckId = $c.Id; Status = $state.Status; Message = $state.Message })
        }
        catch {
            $message = Protect-AdoScopeText "Check $($c.Id) failed: $($_.Exception.Message)"
            Write-Warning $message
            $statuses.Add([pscustomobject]@{ CheckId = $c.Id; Status = 'Error'; Message = $message })
        }
    }

    [pscustomobject]@{ Checks = $statuses.ToArray(); Findings = $findings.ToArray() }
}

function Get-AdoScopeCheckReadiness {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][hashtable]$Check,
        [Parameter(Mandatory)][hashtable]$Context,
        [hashtable]$Parameters = @{}
    )

    $unconfigured = @(foreach ($name in @($Check['RequiredParameters'] | Where-Object { $_ })) {
            $value = $Parameters[$name]
            $empty = if ($value -is [System.Collections.IDictionary]) { $value.Count -eq 0 } else { -not @($value | Where-Object { $_ }).Count }
            if ($empty) { $name }
        })
    if ($unconfigured) {
        return [pscustomobject]@{ Status = 'NotEvaluated'; Message = "Not configured: set Checks.Parameters.$($Check.Id).$($unconfigured -join ', ') in the config, or disable $($Check.Id)." }
    }
    $unavailable = @()
    $partial = @()
    foreach ($name in $Check.Requires) {
        $collection = $Context.Collections[$name]
        if ($null -eq $collection) { $unavailable += "$name (not collected)" }
        elseif ($collection.Status -in 'Failed', 'Forbidden') { $unavailable += "$name ($($collection.Status))" }
        elseif ($collection.Status -eq 'Partial') { $partial += $name }
    }

    if ($unavailable) {
        return [pscustomobject]@{ Status = 'NotEvaluated'; Message = "Required data unavailable: $($unavailable -join ', ')." }
    }
    if ($partial) {
        return [pscustomobject]@{ Status = 'Partial'; Message = "Incomplete data: $($partial -join ', '); findings may be missing." }
    }
    [pscustomobject]@{ Status = 'Evaluated'; Message = $null }
}

function Complete-AdoScopeFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Finding,
        [Parameter(Mandatory)][hashtable]$Check
    )

    foreach ($key in 'Title', 'Category', 'Severity', 'Rationale', 'Remediation') {
        $Finding.$key = $Check[$key]
    }
    $Finding.CheckId = $Check.Id
    $Finding.Fingerprint = Get-AdoScopeFingerprint -CheckId $Check.Id -ResourceId $Finding.ResourceId -Project $Finding.Project
    $Finding
}
