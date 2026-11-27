function Get-AdoRepository {
    <# Git repositories of one project (items already carry project { id; name }). #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    Invoke-AdoScopeListRequest -Uri (Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/git/repositories") -Auth $Auth
}

function Get-AdoRepositoryActivity {
    <#
    .SYNOPSIS
        Latest commit date on the default branch of each active, non-empty repository.
        Separate from Repositories because it costs one call per repository.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    # ponytail: one commits call per repository; batch via Git stats if orgs with thousands of repos get slow.
    foreach ($repo in Get-AdoRepository -Organization $Organization -Auth $Auth -Project $Project) {
        if (-not $repo['defaultBranch'] -or $repo['isDisabled']) { continue }
        $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/git/repositories/$($repo.id)/commits" `
            -Query @{ 'searchCriteria.$top' = 1 }
        $last = (Invoke-AdoScopeRequest -Uri $uri -Auth $Auth).Content?['value'] | Select-Object -First 1
        @{
            id             = $repo.id
            name           = $repo.name
            defaultBranch  = $repo.defaultBranch
            lastCommitDate = ${last}?['committer']?['date']
            _project       = @{ id = $Project.id; name = $Project.name }
        }
    }
}
