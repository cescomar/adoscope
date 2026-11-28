@{
    Id          = 'AGT002'
    Title       = 'Self-hosted agent below minimum version'
    Category    = 'Agents'
    Standards   = @('CICD-SEC-7')
    Severity    = 'Medium'
    Rationale   = 'Only the current major version of the agent receives security patches: Microsoft states that only 5.x agents get patches and that no new 4.x versions are published (Microsoft Learn, "Agent software version 5", 2026). Older agents also run on runtimes that no longer get fixes and can be refused by newer tasks.'
    Remediation = 'Check that the host operating system is supported by .NET 10 (required by agent 5.x), upgrade the OS if needed, then update the agent from the pool page (Agent pools > the pool > Update all agents). Lower minimumVersion in the config only for hosts that cannot be upgraded yet.'
    Parameters  = @{ minimumVersion = '5.0.0' }
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
