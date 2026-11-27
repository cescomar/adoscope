function Get-AdoProject {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    Invoke-AdoScopeListRequest -Uri (Get-AdoScopeApiUri -Organization $Organization -Path '_apis/projects') -Auth $Auth
}
