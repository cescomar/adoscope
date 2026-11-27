function Get-AdoSecureFile {
    <# Secure files (metadata only) of one project with _project and _pipelinePermissions. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/distributedtask/securefiles"
    foreach ($file in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $file._project = @{ id = $Project.id; name = $Project.name }
        Add-AdoScopeEnrichment -Item $file -Key '_pipelinePermissions' -What 'pipeline permissions' -Value {
            Get-AdoPipelinePermission -Organization $Organization -Auth $Auth -Project $Project -ResourceType securefile -ResourceId $file.id
        }
        $file
    }
}
