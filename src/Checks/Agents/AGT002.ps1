@{
    Id          = 'AGT002'
    Title       = 'Self-hosted agent below minimum version'
    Category    = 'Agents'
    Severity    = 'Medium'
    Rationale   = 'Old agent versions run on unsupported runtimes, miss security fixes and are refused by newer tasks. Agent v2 and v3 are out of support.'
    Remediation = 'Update the agent from the pool page (Agent pools > the pool > Update all agents) or reinstall it with the current release; check that the host OS is supported by the new version.'
    Parameters  = @{ minimumVersion = '4.0.0' }
    Requires    = @('AgentPools')
    Test        = {
        param($Context, $Parameters)
        $minimum = [version]$Parameters.minimumVersion
        foreach ($pool in $Context.Collections.AgentPools.Items) {
            # Microsoft-hosted and scale-set (elastic) agents are managed for you.
            if ($pool['isHosted'] -eq $true -or [string]$pool['options'] -match 'elasticPool') { continue }
            foreach ($agent in @($pool['_agents'] | Where-Object { $_ -is [hashtable] })) {
                $version = $agent['version'] -as [version]
                if (-not $version -or $version -ge $minimum) { continue }
                New-AdoScopeFinding -Resource "$($pool.name)/$($agent.name)" -ResourceId "$($pool.id)/$($agent.id)" `
                    -Detail "Agent '$($agent.name)' in pool '$($pool.name)' runs version $version; minimum is $minimum."
            }
        }
    }
}
