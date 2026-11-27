function Get-AdoPipelinePermission {
    <#
    .SYNOPSIS
        Pipeline permissions of one protected resource in one project.
        'allPipelines' is absent unless the resource is open to every pipeline.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project,
        [Parameter(Mandatory)][ValidateSet('endpoint', 'variablegroup', 'securefile')][string]$ResourceType,
        [Parameter(Mandatory)][string]$ResourceId
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/pipelines/pipelinePermissions/$ResourceType/$ResourceId" `
        -ApiVersion $script:PreviewApiVersion.PipelinePermissions
    (Invoke-AdoScopeRequest -Uri $uri -Auth $Auth).Content
}
