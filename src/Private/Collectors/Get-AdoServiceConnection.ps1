function Get-AdoServiceConnection {
    <#
    .SYNOPSIS
        Service connections of one project, each enriched with:
          _project             @{ id; name } of the project it was listed in
          _pipelinePermissions pipeline permissions in that project ('allPipelines' is absent unless open to all)
        A connection shared with several projects appears once per project: permissions are per project.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/serviceendpoint/endpoints"
    foreach ($endpoint in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $endpoint._project = @{ id = $Project.id; name = $Project.name }
        Add-AdoScopeEnrichment -Item $endpoint -Key '_pipelinePermissions' -What 'pipeline permissions' -Value {
            Get-AdoPipelinePermission -Organization $Organization -Auth $Auth -Project $Project -ResourceType endpoint -ResourceId $endpoint.id
        }
        $endpoint
    }
}
