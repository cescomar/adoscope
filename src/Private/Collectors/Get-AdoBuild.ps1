function Get-AdoBuild {
    <#
    .SYNOPSIS
        Last completed builds (up to 50 per definition) of one project, trimmed to the
        fields checks use, in one paged call (no per-definition requests).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $query = @{ maxBuildsPerDefinition = 50; queryOrder = 'finishTimeDescending'; statusFilter = 'completed' }
    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/build/builds" -Query $query
    foreach ($build in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        @{
            id         = $build.id
            result     = $build['result']
            finishTime = $build['finishTime']
            definition = @{ id = $build['definition']?['id']; name = $build['definition']?['name'] }
            project    = @{ id = $Project.id; name = $Project.name }
        }
    }
}
