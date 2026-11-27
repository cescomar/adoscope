function Get-AdoUserEntitlement {
    <# Organization users with license (accessLevel) and last access (vsaex service). #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path '_apis/userentitlements' -Service vsaex `
        -ApiVersion $script:PreviewApiVersion.UserEntitlements
    foreach ($entitlement in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth -ItemProperty 'members') {
        @{
            id               = $entitlement.id
            # descriptor matches the Graph descriptor used in group memberships (verified live).
            user             = @{ displayName = $entitlement['user']?['displayName']; principalName = $entitlement['user']?['principalName']; descriptor = $entitlement['user']?['descriptor'] }
            accessLevel      = $entitlement['accessLevel']
            lastAccessedDate = $entitlement['lastAccessedDate']
            dateCreated      = $entitlement['dateCreated']
        }
    }
}
