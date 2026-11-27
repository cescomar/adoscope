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

    Write-Host "adoscope $($Report.Version) - organization '$($Report.Organization)' - $($Report.GeneratedAt)"
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
    $baseline = if ($Report.Baseline) { " | new: $($Report.Baseline.New), resolved since baseline: $($Report.Baseline.Resolved)" } else { '' }
    Write-Host "Summary - $($counts -join ', ') | suppressed: $suppressed$baseline | checks: $evaluated/$enabled fully evaluated"
}
