function Show-AdoScopeConsoleReport {
    <#
    .SYNOPSIS
        Human-readable report: findings grouped by severity (highest first),
        then checks that could not be evaluated, then a summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report
    )

    $colors = @{ Critical = 'Magenta'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
    $active = @($Report.Findings | Where-Object { -not $_.Suppressed })

    Write-Host "adoscope $($Report.Version) - organization '$($Report.Organization)' - data collected $($Report.Scope.CollectedAt) ($($Report.Scope.Mode)), $(@($Report.Scope.Projects).Count) project(s)"
    for ($i = $script:Severities.Count - 1; $i -ge 0; $i--) {
        $severity = $script:Severities[$i]
        $group = @($active | Where-Object Severity -eq $severity | Sort-Object CheckId, Project, Resource)
        if (-not $group) { continue }
        Write-Host ''
        Write-Host "$severity ($($group.Count))" -ForegroundColor $colors[$severity]
        foreach ($f in $group) {
            $target = if ($f.Project) { "$($f.Project)/$($f.Resource)" } else { $f.Resource }
            $known = if ($f.InBaseline) { ' (baseline)' } else { '' }
            Write-Host "  [$($f.CheckId)] $($f.Title): $target$known" -ForegroundColor $colors[$severity]
            Write-Host "      $($f.Detail)"
        }
    }

    # Per collection: what the identity could not read and which checks lose coverage.
    $unreadable = @($Report.Collections | Where-Object Status -ne 'Ok')
    if ($unreadable) {
        Write-Host ''
        Write-Host "Data not fully read ($($unreadable.Count))" -ForegroundColor Yellow
        foreach ($c in $unreadable) {
            $hint = if ($c.Status -eq 'Forbidden') { 'Access denied: grant the audit identity read access to it.' } else { $c.Error }
            Write-Host "  $($c.Name) $($c.Status) - $($c.Source)"
            Write-Host "      $hint$(if ($c.AffectedChecks) { " Affects: $($c.AffectedChecks -join ', ')." })"
        }
    }

    $incomplete = @($Report.Checks | Where-Object Status -notin 'Evaluated', 'Disabled')
    if ($incomplete) {
        Write-Host ''
        Write-Host "Coverage gaps ($($incomplete.Count))" -ForegroundColor Yellow
        foreach ($c in $incomplete) { Write-Host "  [$($c.CheckId)] $($c.Status): $($c.Message)" }
    }

    # Expired: the exception lapsed and its findings are back. Unmatched: nothing left to suppress.
    $stale = @($Report.Suppressions | Where-Object Status -ne 'Active')
    if ($stale) {
        Write-Host ''
        Write-Host "Configuration ($($stale.Count))" -ForegroundColor Yellow
        foreach ($s in $stale) { Write-Host "  [$($s.Check)] suppression $($s.Status) (expires $($s.Expires)): $($s.Target)" }
    }

    $counts = foreach ($severity in $script:Severities[($script:Severities.Count - 1)..0]) {
        '{0}: {1}' -f $severity, @($active | Where-Object Severity -eq $severity).Count
    }
    $suppressed = @($Report.Findings | Where-Object Suppressed).Count
    $evaluated = @($Report.Checks | Where-Object Status -eq 'Evaluated').Count
    $enabled = @($Report.Checks | Where-Object Status -ne 'Disabled').Count
    Write-Host ''
    $baseline = if ($Report.Baseline) { " | new: $($Report.Baseline.New), resolved since baseline: $($Report.Baseline.Resolved), gone but unverified: $($Report.Baseline.Unverified)" } else { '' }
    Write-Host "Summary - $($counts -join ', ') | suppressed: $suppressed$baseline | checks: $evaluated/$enabled fully evaluated"
}
