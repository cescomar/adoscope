function Get-AdoPersonalAccessToken {
    <#
    .SYNOPSIS
        Personal access tokens of every licensed user (Token Admin API, vssps), reduced to
        metadata: name, scope, validity, target organizations. Token values are never kept;
        the API returned them empty when observed, and the allow-list keeps it that way.
        A user whose tokens cannot be read is marked (_error), not dropped silently.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    $usersUri = Get-AdoScopeApiUri -Organization $Organization -Path '_apis/userentitlements' -Service vsaex `
        -ApiVersion $script:PreviewApiVersion.UserEntitlements
    foreach ($entitlement in Invoke-AdoScopeListRequest -Uri $usersUri -Auth $Auth -ItemProperty 'members') {
        $descriptor = $entitlement['user']?['descriptor']
        if (-not $descriptor) { continue }
        $user = [string]($entitlement['user']?['principalName'] ?? $descriptor)
        $holder = @{ name = $user }
        Add-AdoScopeEnrichment -Item $holder -Key 'tokens' -What 'personal access tokens' -Value {
            $uri = Get-AdoScopeApiUri -Organization $Organization -Path "_apis/tokenadmin/personalaccesstokens/$descriptor" -Service vssps
            , @(Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth)
        }
        if ($holder['_error']) { @{ user = $user; userDescriptor = $descriptor; _error = $holder._error }; continue }
        foreach ($t in $holder.tokens) {
            $targets = $t['targetAccounts']
            @{
                user             = $user
                userDescriptor   = $descriptor
                authorizationId  = [string]$t['authorizationId']
                displayName      = $t['displayName']
                scope            = [string]$t['scope']
                validFrom        = $t['validFrom']
                validTo          = $t['validTo']
                isValid          = $t['isValid'] -eq $true
                # No target list means the token works in every organization the user can access.
                allOrganizations = $null -eq $targets -or @($targets).Count -eq 0
            }
        }
    }
}
