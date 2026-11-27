function Get-AdoEnvironment {
    <#
    .SYNOPSIS
        Deployment environments of one project with _project and _checks (approvals and
        checks: type.name is Approval, ExtendsCheck = Required template, Task Check, ...).
        Uses the GET list per environment, not the POST query endpoint, so the client
        stays GET-only.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/distributedtask/environments"
    foreach ($environment in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $checksUri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/pipelines/checks/configurations" `
            -Query @{ resourceType = 'environment'; resourceId = $environment.id } -ApiVersion $script:PreviewApiVersion.CheckConfigurations
        $environment._project = @{ id = $Project.id; name = $Project.name }
        # On failure _checks is $null (unknown), never an empty list: PIP001/PIP002 must not report "no checks".
        Add-AdoScopeEnrichment -Item $environment -Key '_checks' -What 'approvals and checks' -Value {
            , @(Invoke-AdoScopeListRequest -Uri $checksUri -Auth $Auth | ForEach-Object {
                    @{ id = $_.id; type = $_['type']; isDisabled = $_['isDisabled'] -eq $true }
                })
        }
        $environment
    }
}
