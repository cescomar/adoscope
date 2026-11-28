$script:ApiVersion = '7.1'
# Endpoints that only exist as previews; one place to bump them.
$script:PreviewApiVersion = @{
    PipelinePermissions  = '7.1-preview.1'
    BuildGeneralSettings = '7.1-preview.1'
    CheckConfigurations  = '7.1-preview.1'
    Graph                = '7.1-preview.1'
    ExtensionManagement  = '7.1-preview.1'
    UserEntitlements     = '7.1-preview.3'
}
$script:AllowedHosts = @('dev.azure.com', 'vsaex.dev.azure.com', 'vssps.dev.azure.com', 'vsrm.dev.azure.com', 'extmgmt.dev.azure.com')
$script:MaxAttempts = 5

function Invoke-AdoScopeRequest {
    <#
    .SYNOPSIS
        The only function that talks to Azure DevOps. GET only, allow-listed hosts
        only, no redirects (credentials never follow a 302), retries on throttling.
        Returns @{ Content = <hashtable>; ContinuationToken = <string|null> }.
        Failures throw HttpRequestException with StatusCode set (403 -> Forbidden collection).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [string]$Method = 'GET'
    )

    if ($Method -ne 'GET') { throw "adoscope is read-only: refused $Method $($Uri.AbsolutePath)." }
    Assert-AdoScopeHost -Uri $Uri
    $headers = @{ Authorization = Get-AdoScopeAuthorizationHeader -Auth $Auth; Accept = 'application/json' }
    $refreshed = $false

    for ($attempt = 1; ; $attempt++) {
        # Network failures are terminating and propagate. A blocked redirect (invalid PAT ->
        # sign-in page) only writes a non-terminating error and still returns the 302 response.
        $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $headers -SkipHttpErrorCheck -MaximumRedirection 0 `
            -ErrorAction SilentlyContinue
        if ($null -eq $response) { throw "GET $($Uri.AbsolutePath) returned no response." }
        $status = [int]$response.StatusCode
        if ($status -in 429, 503 -and $attempt -lt $script:MaxAttempts) {
            $retryAfter = Get-AdoScopeHeader -Response $response -Name 'Retry-After'
            $delay = if ($retryAfter -as [int]) { [int]$retryAfter } else { [math]::Pow(2, $attempt) }
            Write-Verbose "HTTP $status on $($Uri.AbsolutePath); retry $attempt in ${delay}s."
            Start-Sleep -Seconds $delay
            continue
        }
        # Entra tokens expire (about 1 hour); long audits outlive them. Tokens from Azure CLI or
        # Az can be re-issued: refresh once and retry. A PAT cannot, so its failure stands.
        $authFailed = $status -in 401, 203 -or ($status -ge 300 -and $status -lt 400)
        if ($authFailed -and -not $refreshed -and $Auth.Source -in 'Azure CLI', 'Az PowerShell') {
            $refreshed = $true
            $fresh = Get-AdoScopeAzureToken
            if ($fresh) {
                Write-Verbose "Access token rejected (HTTP $status); using a new token from $($fresh.Source)."
                $Auth.Secret = $fresh.Secret
                $headers.Authorization = Get-AdoScopeAuthorizationHeader -Auth $Auth
                continue
            }
        }
        $result = ConvertFrom-AdoScopeResponse -Response $response -Uri $Uri
        # Azure DevOps announces throttling on successful responses before it starts rejecting:
        # pausing here keeps large audits from being blocked.
        $wait = (Get-AdoScopeHeader -Response $response -Name 'Retry-After') -as [int]
        if ($wait -gt 0) {
            $remaining = Get-AdoScopeHeader -Response $response -Name 'X-RateLimit-Remaining'
            Write-Verbose "Azure DevOps is throttling (X-RateLimit-Remaining: $remaining); pausing ${wait}s."
            Start-Sleep -Seconds $wait
        }
        return $result
    }
}

function ConvertFrom-AdoScopeResponse {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][uri]$Uri
    )

    $status = [int]$Response.StatusCode
    $isJson = (Get-AdoScopeHeader -Response $Response -Name 'Content-Type') -match 'application/json'
    $where = "GET $($Uri.AbsolutePath)"

    # Invalid PAT: Azure DevOps answers 203 or a redirect with an HTML sign-in page, not 401.
    if ($status -eq 401 -or $status -eq 203 -or ($status -ge 300 -and $status -lt 400) -or ($status -eq 200 -and -not $isJson)) {
        throw [System.Net.Http.HttpRequestException]::new(
            "$where - authentication failed (HTTP $status). Check the token, its expiry and its scopes.", $null, [System.Net.HttpStatusCode]::Unauthorized)
    }
    $content = if ($isJson -and $Response.Content) { $Response.Content | ConvertFrom-Json -AsHashtable -Depth 100 } else { $null }
    if ($status -ge 400) {
        $detail = if ($content -is [hashtable] -and $content['message']) { ": $($content.message)" } else { '' }
        throw [System.Net.Http.HttpRequestException]::new(
            (Protect-AdoScopeText "$where returned HTTP $status$detail"), $null, [System.Net.HttpStatusCode]$status)
    }
    [pscustomobject]@{
        Content           = $content
        ContinuationToken = Get-AdoScopeHeader -Response $Response -Name 'x-ms-continuationtoken'
    }
}

function Invoke-AdoScopeListRequest {
    <# Follows continuation tokens (header or body) and emits every item of every page. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        # 'value' for most list APIs; 'members' for user entitlements.
        [string]$ItemProperty = 'value'
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $pageUri = $Uri
    while ($true) {
        $page = Invoke-AdoScopeRequest -Uri $pageUri -Auth $Auth
        $content = $page.Content
        if ($content -is [hashtable]) { foreach ($item in @($content[$ItemProperty])) { if ($null -ne $item) { $item } } }

        $token = $page.ContinuationToken
        if (-not $token -and $content -is [hashtable]) { $token = $content['continuationToken'] }
        if (-not $token) { return }
        if (-not $seen.Add($token)) { throw "Paging loop detected on GET $($Uri.AbsolutePath): continuation token repeated." }
        $separator = if ($Uri.Query) { '&' } else { '?' }
        $pageUri = [uri]"$Uri${separator}continuationToken=$([uri]::EscapeDataString($token))"
    }
}

function Assert-AdoScopeHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri]$Uri)

    $allowed = $Uri.Scheme -eq 'https' -and ($Uri.Host -in $script:AllowedHosts -or $Uri.Host -like '*.visualstudio.com')
    if (-not $allowed) { throw "Refused to send credentials to '$($Uri.Scheme)://$($Uri.Host)': not an Azure DevOps Services host." }
}

function Get-AdoScopeHeader {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object]$Response,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Response.Headers -or -not $Response.Headers.ContainsKey($Name)) { return $null }
    @($Response.Headers[$Name])[0]
}

function Get-AdoScopeApiUri {
    <#
    .SYNOPSIS
        Builds an API URI. Path segments that may contain spaces (project names)
        must be escaped by the caller with [uri]::EscapeDataString.
    #>
    [CmdletBinding()]
    [OutputType([uri])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Query = @{},
        [ValidateSet('dev', 'vsaex', 'vssps', 'vsrm', 'extmgmt')][string]$Service = 'dev',
        [string]$ApiVersion = $script:ApiVersion
    )

    $hostName = if ($Service -eq 'dev') { 'dev.azure.com' } else { "$Service.dev.azure.com" }
    $pairs = @("api-version=$ApiVersion") + @($Query.Keys | Sort-Object | ForEach-Object {
            '{0}={1}' -f $_, [uri]::EscapeDataString([string]$Query[$_])
        })
    [uri]"https://$hostName/$Organization/$($Path.TrimStart('/'))?$($pairs -join '&')"
}

function ConvertTo-AdoScopeOrganization {
    <# Accepts 'org', 'dev.azure.com/org', 'https://dev.azure.com/org/' or 'https://org.visualstudio.com'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Value)

    $v = $Value.Trim() -replace '^https?://', '' -replace '/+$', ''
    $name = switch -Regex ($v) {
        '^dev\.azure\.com/([^/]+)$' { $Matches[1]; break }
        '^([^./]+)\.visualstudio\.com$' { $Matches[1]; break }
        '^[^./]+$' { $v; break }
        default { $null }
    }
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,48}$') { throw "Invalid Azure DevOps organization '$Value'." }
    $name
}
