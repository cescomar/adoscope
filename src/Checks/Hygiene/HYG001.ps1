@{
    Id          = 'HYG001'
    Title       = 'Pipeline not run recently'
    Category    = 'Hygiene'
    Severity    = 'Low'
    Rationale   = 'Pipelines nobody runs still hold permissions on service connections, agent pools and repositories, clutter the catalog and hide which automation is actually in use.'
    Remediation = 'Confirm with the owner, then delete the pipeline or disable it (Settings > Disabled). Keep the YAML in the repository history if it may be needed again.'
    Parameters  = @{ days = 90 }
    Requires    = @('BuildDefinitions')
    Test        = {
        param($Context, $Parameters)
        # Measured from collection time, not now: offline re-runs give the same answer.
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($definition in $Context.Collections.BuildDefinitions.Items) {
            $last = $definition['latestBuild']?['finishTime'] ?? $definition['latestBuild']?['queueTime']
            if ($last) {
                $age = [int]($now - ([datetime]$last).ToUniversalTime()).TotalDays
                $detail = "Last run $age days ago."
            }
            elseif ($definition['createdDate']) {
                $age = [int]($now - ([datetime]$definition.createdDate).ToUniversalTime()).TotalDays
                $detail = "Never run; created $age days ago."
            }
            else { continue }   # no dates: cannot tell
            if ($age -lt $Parameters.days) { continue }
            New-AdoScopeFinding -Project $definition['project']?['name'] -Resource $definition.name -ResourceId ([string]$definition.id) `
                -Detail "$detail Threshold: $($Parameters.days) days."
        }
    }
}
