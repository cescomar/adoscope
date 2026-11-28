@{
    Id          = 'REL001'
    Title       = 'Pipeline fails too often'
    Category    = 'Reliability'
    Severity    = 'Medium'
    Rationale   = 'A pipeline that fails often trains people to ignore red builds and re-run until green, so real defects and security gate failures slip through; it also wastes agent time and delays delivery.'
    Remediation = 'Open the recent failed runs, separate flaky tests and infrastructure errors from real defects, fix or quarantine the flaky parts, and track the failure rate until it is below the threshold.'
    # Canceled runs are ignored; partiallySucceeded counts as success. runs <= 50 (collector limit).
    Parameters  = @{ runs = 20; minimumRuns = 5; maxFailureRate = 0.3 }
    Validate    = {
        param($Parameters)
        if ($Parameters.runs -gt 50) { 'runs must be at most 50 (runs collected per pipeline)' }
        if ($Parameters.minimumRuns -gt $Parameters.runs) { "minimumRuns ($($Parameters.minimumRuns)) must not exceed runs ($($Parameters.runs))" }
        if ($Parameters.maxFailureRate -ge 1) { 'maxFailureRate is a fraction below 1 (0.3 = 30%)' }
    }
    Requires    = @('Builds')
    Test        = {
        param($Context, $Parameters)
        $byDefinition = $Context.Collections.Builds.Items |
            Where-Object { $_['result'] -and $_['result'] -ne 'canceled' -and $_['finishTime'] -and $_['definition']?['id'] } |
            Group-Object { "$($_['project']?['name'])|$($_.definition.id)" }
        foreach ($group in $byDefinition) {
            $recent = @($group.Group | Sort-Object { [datetime]$_['finishTime'] } -Descending | Select-Object -First $Parameters.runs)
            if ($recent.Count -lt $Parameters.minimumRuns) { continue }
            $failed = @($recent | Where-Object { $_['result'] -eq 'failed' }).Count
            $rate = $failed / $recent.Count
            if ($rate -le $Parameters.maxFailureRate) { continue }
            $first = $recent[0]
            $detail = "$failed of the last $($recent.Count) runs failed ($([int][math]::Round($rate * 100))%); " +
            "threshold $([int][math]::Round($Parameters.maxFailureRate * 100))%."
            New-AdoScopeFinding -Project $first['project']?['name'] -Resource $first.definition['name'] -ResourceId ([string]$first.definition.id) -Detail $detail
        }
    }
}
