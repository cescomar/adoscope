function Get-AdoPolicy {
    <# Branch policy configurations of one project, with _project. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/policy/configurations"
    foreach ($policy in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $policy._project = @{ id = $Project.id; name = $Project.name }
        $policy
    }
}
