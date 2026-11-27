function Get-AdoAgentPool {
    <#
    .SYNOPSIS
        Organization agent pools. Self-hosted pools get _agents; Microsoft-hosted pools
        (isHosted) report placeholder agents and are not expanded.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    foreach ($pool in Invoke-AdoScopeListRequest -Uri (Get-AdoScopeApiUri -Organization $Organization -Path '_apis/distributedtask/pools') -Auth $Auth) {
        $pool._agents = @()
        if ($pool['isHosted'] -ne $true) {
            $agentsUri = Get-AdoScopeApiUri -Organization $Organization -Path "_apis/distributedtask/pools/$($pool.id)/agents"
            $pool._agents = @(Invoke-AdoScopeListRequest -Uri $agentsUri -Auth $Auth)
        }
        $pool
    }
}

function Get-AdoAgentQueue {
    <# Agent queues of one project: which pools the project can use (queue.pool carries isHosted). #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    foreach ($queue in Invoke-AdoScopeListRequest -Uri (Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/distributedtask/queues") -Auth $Auth) {
        $queue._project = @{ id = $Project.id; name = $Project.name }
        $queue
    }
}
