function Get-AdoVariableGroup {
    <#
    .SYNOPSIS
        Variable groups of one project with _project and _pipelinePermissions.
        VALUES ARE NEVER KEPT: the API returns non-secret values in clear text, and a
        saved context must not contain credentials. Each variable keeps only:
          isSecret, _valueLooksLikeCredential (value matched a credential pattern)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/distributedtask/variablegroups"
    foreach ($group in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $item = @{
            id        = $group.id
            name      = $group.name
            type      = $group['type']
            variables = ConvertTo-AdoScopeVariableSummary -Variable $group['variables']
            _project  = @{ id = $Project.id; name = $Project.name }
        }
        Add-AdoScopeEnrichment -Item $item -Key '_pipelinePermissions' -What 'pipeline permissions' -Value {
            Get-AdoPipelinePermission -Organization $Organization -Auth $Auth -Project $Project -ResourceType variablegroup -ResourceId ([string]$group.id)
        }
        $item
    }
}
