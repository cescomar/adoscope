$script:AdoResourceId = '499b84ac-1321-427f-aa17-267ca6975798'

function Resolve-AdoScopeAuth {
    <#
    .SYNOPSIS
        Picks credentials in order: -AccessToken, -Pat, $env:AZURE_DEVOPS_EXT_PAT,
        Azure CLI / Az session, $env:SYSTEM_ACCESSTOKEN. Secrets stay SecureString;
        the plain value only exists while building a request header.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [securestring]$AccessToken,
        [securestring]$Pat
    )

    if ($AccessToken) { return [pscustomobject]@{ Scheme = 'Bearer'; Secret = $AccessToken; Source = '-AccessToken' } }
    if ($Pat) { return [pscustomobject]@{ Scheme = 'Basic'; Secret = $Pat; Source = '-Pat' } }
    if ($env:AZURE_DEVOPS_EXT_PAT) {
        $secret = ConvertTo-AdoScopeSecureString -Value $env:AZURE_DEVOPS_EXT_PAT
        return [pscustomobject]@{ Scheme = 'Basic'; Secret = $secret; Source = 'AZURE_DEVOPS_EXT_PAT' }
    }
    $azure = Get-AdoScopeAzureToken
    if ($azure) { return $azure }
    if ($env:SYSTEM_ACCESSTOKEN) {
        Write-Warning 'Using SYSTEM_ACCESSTOKEN: the build service identity sees only part of the organization; expect NotEvaluated checks.'
        $secret = ConvertTo-AdoScopeSecureString -Value $env:SYSTEM_ACCESSTOKEN
        return [pscustomobject]@{ Scheme = 'Bearer'; Secret = $secret; Source = 'SYSTEM_ACCESSTOKEN' }
    }
    throw 'No Azure DevOps credentials found. Use -AccessToken or -Pat, set AZURE_DEVOPS_EXT_PAT, or sign in with "az login".'
}

function Get-AdoScopeAzureToken {
    <# Entra ID token from an existing Azure CLI or Az PowerShell session; $null if none. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    if (Get-Command az -CommandType Application -ErrorAction Ignore) {
        $json = az account get-access-token --resource $script:AdoResourceId --output json 2>$null
        if ($LASTEXITCODE -eq 0 -and $json) {
            $secret = ConvertTo-AdoScopeSecureString -Value ($json | ConvertFrom-Json).accessToken
            return [pscustomobject]@{ Scheme = 'Bearer'; Secret = $secret; Source = 'Azure CLI' }
        }
    }
    if (Get-Module Az.Accounts) {
        try {
            $token = (Get-AzAccessToken -ResourceUrl $script:AdoResourceId -ErrorAction Stop).Token
            if ($token -isnot [securestring]) { $token = ConvertTo-AdoScopeSecureString -Value $token }   # Az < 14
            return [pscustomobject]@{ Scheme = 'Bearer'; Secret = $token; Source = 'Az PowerShell' }
        }
        catch {
            Write-Verbose "Az PowerShell session unusable: $(Protect-AdoScopeText $_.Exception.Message)"
        }
    }
    $null
}

function ConvertTo-AdoScopeSecureString {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Wraps tokens that arrive as plain text (env vars, CLI output) so they are not kept as strings.')]
    [CmdletBinding()]
    [OutputType([securestring])]
    param([Parameter(Mandatory)][string]$Value)

    ConvertTo-SecureString -String $Value -AsPlainText -Force
}

function Get-AdoScopeAuthorizationHeader {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Auth)

    $plain = ConvertFrom-SecureString -SecureString $Auth.Secret -AsPlainText
    if ($Auth.Scheme -eq 'Basic') {
        # PAT: Basic auth with an empty user name.
        return 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$plain"))
    }
    "Bearer $plain"
}

function Copy-AdoScopeAuth {
    <# Independent copy (own SecureString) for use on another thread. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Auth)

    [pscustomobject]@{ Scheme = $Auth.Scheme; Secret = $Auth.Secret.Copy(); Source = $Auth.Source }
}
