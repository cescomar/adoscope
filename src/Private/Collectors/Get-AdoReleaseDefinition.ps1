function Get-AdoReleaseDefinition {
    <#
    .SYNOPSIS
        Classic release definitions of one project (vsrm), reduced to an allow-list of fields.
        The list endpoint omits stage approvals and variables, so each definition is read
        once more; a failed read marks only that definition (_error). Variables keep no values.
        Shape follows the official schema (Definitions - Get, 7.1): the test organization has
        no classic releases and forbids creating them, so it is not verified live.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/release/definitions" -Service vsrm
    foreach ($listed in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        $item = @{ id = $listed.id; name = $listed.name; path = $listed['path']; project = @{ id = $Project.id; name = $Project.name } }
        Add-AdoScopeEnrichment -Item $item -Key '_definition' -What 'release definition' -Value {
            $getUri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/release/definitions/$($listed.id)" -Service vsrm
            ConvertTo-AdoScopeReleaseSummary -Definition (Invoke-AdoScopeRequest -Uri $getUri -Auth $Auth).Content
        }
        if ($item['_definition']) {
            $item.variables = $item._definition.variables
            $item.environments = $item._definition.environments
        }
        $item.Remove('_definition')
        $item
    }
}

function ConvertTo-AdoScopeReleaseSummary {
    <# Variables (without values) and per-stage approval settings of a full release definition. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable]$Definition)

    @{
        variables    = ConvertTo-AdoScopeVariableSummary -Variable $Definition['variables']
        environments = @(@($Definition['environments']) | Where-Object { $_ -is [hashtable] } | ForEach-Object {
                $pre = $_['preDeployApprovals']
                @{
                    id                          = $_['id']
                    name                        = $_['name']
                    variables                   = ConvertTo-AdoScopeVariableSummary -Variable $_['variables']
                    approvals                   = @(@(${pre}?['approvals']) | Where-Object { $_ -is [hashtable] } | ForEach-Object { @{ isAutomated = $_['isAutomated'] -eq $true } })
                    releaseCreatorCanBeApprover = ${pre}?['approvalOptions']?['releaseCreatorCanBeApprover']
                    gates                       = @(@($_['preDeploymentGates']?['gates']) | Where-Object { $null -ne $_ }).Count
                }
            })
    }
}
