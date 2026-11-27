function Get-AdoBuildDefinition {
    <#
    .SYNOPSIS
        Build definitions of one project, reduced to the fields checks use (allow-list).
        includeAllProperties is required (without it the list omits process and triggers), but
        full definitions also carry plain-text variable values and classic task inputs such as
        inline scripts: keeping them would copy credentials into saved contexts (reproduced in
        the lab). Variables keep only isSecret / _valueLooksLikeCredential.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $query = @{ includeLatestBuilds = 'true'; includeAllProperties = 'true' }
    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/build/definitions" -Query $query
    foreach ($d in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $latest = $d['latestBuild']
        @{
            id          = $d.id
            name        = $d.name
            path        = $d['path']
            queueStatus = $d['queueStatus']
            createdDate = $d['createdDate']
            project     = @{ id = $Project.id; name = $Project.name }
            process     = @{ type = $d['process']?['type'] }
            repository  = @{ type = $d['repository']?['type'] }
            latestBuild = if ($latest -is [hashtable]) { @{ queueTime = $latest['queueTime']; finishTime = $latest['finishTime']; result = $latest['result'] } } else { $null }
            triggers    = @(@($d['triggers']) | Where-Object { $_ -is [hashtable] } | ForEach-Object {
                    $forks = $_['forks']
                    @{
                        triggerType = $_['triggerType']
                        forks       = if ($forks -is [hashtable]) { @{ enabled = $forks['enabled']; allowSecrets = $forks['allowSecrets']; allowFullAccessToken = $forks['allowFullAccessToken'] } } else { $null }
                    }
                })
            variables   = ConvertTo-AdoScopeVariableSummary -Variable $d['variables']
        }
    }
}
