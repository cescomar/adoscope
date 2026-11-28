function Get-AdoInstalledExtension {
    <#
    .SYNOPSIS
        Extensions installed in the organization (extmgmt service), reduced to identity, state
        and requested OAuth scopes. Observed live: built-in Microsoft extensions carry
        flags 'builtIn, trusted' and no scopes.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path '_apis/extensionmanagement/installedextensions' -Service extmgmt `
        -ApiVersion $script:PreviewApiVersion.ExtensionManagement
    foreach ($e in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
        @{
            publisherId   = $e['publisherId']
            publisherName = $e['publisherName']
            extensionId   = $e['extensionId']
            extensionName = $e['extensionName']
            version       = $e['version']
            flags         = [string]$e['flags']
            installFlags  = [string]$e['installState']?['flags']
            scopes        = @($e['scopes'] | Where-Object { $_ })
        }
    }
}
