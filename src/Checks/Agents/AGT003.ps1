@{
    Id          = 'AGT003'
    Title       = 'Self-hosted agent offline for a long time'
    Category    = 'Agents'
    Standards   = @('CICD-SEC-7')
    Severity    = 'Low'
    Rationale   = 'An agent offline for weeks is usually a decommissioned machine still registered: it keeps its access token, clutters capacity planning and may come back unpatched.'
    Remediation = 'Confirm the machine is gone, then remove the agent from the pool (Agent pools > the pool > Agents > Delete). If it is still needed, bring it back online and patch it first.'
    Parameters  = @{ days = 30 }
    Requires    = @('AgentPools')
    Test        = {
        param($Context, $Parameters)
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($pool in $Context.Collections.AgentPools.Items) {
            if ($pool['isHosted'] -eq $true -or [string]$pool['options'] -match 'elasticPool') { continue }
            foreach ($agent in @($pool['_agents'] | Where-Object { $_ -is [hashtable] })) {
                if ($agent['status'] -ne 'offline' -or -not $agent['statusChangedOn']) { continue }
                $days = [int]($now - ([datetime]$agent.statusChangedOn).ToUniversalTime()).TotalDays
                if ($days -lt $Parameters.days) { continue }
                New-AdoScopeFinding -Resource "$($pool.name)/$($agent.name)" -ResourceId "$($pool.id)/$($agent.id)" `
                    -Detail "Agent '$($agent.name)' in pool '$($pool.name)' has been offline for $days days; threshold $($Parameters.days)."
            }
        }
    }
}
