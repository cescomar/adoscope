@{
    Id          = 'AGT001'
    Title       = 'Self-hosted agent pool shared across trust boundaries'
    Category    = 'Agents'
    Severity    = 'High'
    Rationale   = 'Self-hosted agents keep files, caches and credentials between jobs. A pool used by projects of different trust levels lets a pipeline in a low-trust project tamper with the agent and then read or alter what a high-trust project builds or deploys.'
    Remediation = 'Give each trust group its own agent pool (or use ephemeral agents, e.g. scale-set agents with "tear down after each use"), and remove the pool from the projects of the other groups in Project settings > Agent pools.'
    # Example: @{ production = @('payments', 'core'); sandbox = @('playground') }. Projects not listed are ignored.
    Parameters  = @{ trustGroups = @{} }
    Requires    = @('AgentQueues')
    Test        = {
        param($Context, $Parameters)
        $groupOf = @{}
        foreach ($group in $Parameters.trustGroups.Keys) {
            foreach ($project in @($Parameters.trustGroups[$group])) { $groupOf[[string]$project] = $group }
        }
        $selfHosted = $Context.Collections.AgentQueues.Items | Where-Object { $_['pool'] -is [hashtable] -and $_.pool['isHosted'] -ne $true }
        foreach ($pool in $selfHosted | Group-Object { $_.pool['id'] }) {
            $projects = @($pool.Group | ForEach-Object { [string]$_['_project']?['name'] } | Sort-Object -Unique)
            $groups = @($projects | Where-Object { $groupOf.ContainsKey($_) } | ForEach-Object { $groupOf[$_] } | Sort-Object -Unique)
            if ($groups.Count -lt 2) { continue }
            $poolName = $pool.Group[0].pool['name']
            New-AdoScopeFinding -Resource $poolName -ResourceId ([string]$pool.Name) `
                -Detail "Pool '$poolName' is used by trust groups $($groups -join ', ') (projects: $($projects -join ', '))."
        }
    }
}
