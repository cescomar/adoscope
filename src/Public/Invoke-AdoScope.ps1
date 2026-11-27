function Invoke-AdoScope {
    <#
    .SYNOPSIS
        Audits an Azure DevOps Services organization and reports findings.

    .DESCRIPTION
        Collects the organization configuration once through the REST API (GET only),
        runs every enabled check, and emits console, JSON, SARIF, or HTML reports.
        Checks with unavailable data are reported as NotEvaluated, never as clean.

    .PARAMETER JsonPath
        Writes the report JSON to this UTF-8 without BOM file.

    .PARAMETER SarifPath
        Writes a SARIF 2.1.0 report to this UTF-8 without BOM file.

    .PARAMETER HtmlPath
        Writes a self-contained HTML report to this UTF-8 without BOM file.

    .PARAMETER Quiet
        Suppresses the console report.

    .PARAMETER ThrottleLimit
        Projects collected in parallel (1 = sequential). Default 4. Azure DevOps throttling
        is honored per request, so raising it trades speed for a higher chance of being slowed down.

    .PARAMETER BaselinePath
        Previous adoscope JSON report (from -JsonPath). Findings already in it are marked
        InBaseline; the report counts new and resolved findings, and adoscope.ps1 -FailOn
        blocks only new ones. Lets a team adopt the gate without fixing all existing debt first.

    .EXAMPLE
        Invoke-AdoScope -Organization fabrikam

        Audits an organization and prints the console report.

    .EXAMPLE
        Invoke-AdoScope -ContextPath ./context.json -JsonPath ./report.json -SarifPath ./report.sarif -HtmlPath ./report.html -Quiet

        Re-runs checks offline and writes all file formats without console output.

    .EXAMPLE
        Invoke-AdoScope -ConfigPath ./adoscope.config.psd1 -PassThru

        Uses configuration settings and returns the report object.

    .EXAMPLE
        Invoke-AdoScope -Organization fabrikam -BaselinePath ./baseline.json -JsonPath ./report.json

        Compares with an earlier report: shows what is new and what was fixed since then.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Live', Position = 0)][string]$Organization,
        [Parameter(ParameterSetName = 'Live')][string[]]$Project,
        [Parameter(ParameterSetName = 'Live')][securestring]$AccessToken,
        [Parameter(ParameterSetName = 'Live')][securestring]$Pat,
        [Parameter(ParameterSetName = 'Live')][string]$SaveContextPath,
        [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$ContextPath,
        [string]$ConfigPath,
        [string]$BaselinePath,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 16)][int]$ThrottleLimit = 4,
        [string[]]$CheckPath = $script:CheckRoot,
        [string]$JsonPath,
        [string]$SarifPath,
        [string]$HtmlPath,
        [switch]$Quiet,
        [switch]$PassThru
    )

    $auditParameters = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -notin 'JsonPath', 'SarifPath', 'HtmlPath', 'Quiet', 'PassThru') { $auditParameters[$name] = $PSBoundParameters[$name] }
    }
    $report = Invoke-AdoScopeAudit @auditParameters
    Write-AdoScopeReportOutput -Report $report -JsonPath $JsonPath -SarifPath $SarifPath -HtmlPath $HtmlPath -Quiet:$Quiet
    if ($PassThru) { $report }
}

function Invoke-AdoScopeAudit {
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(ParameterSetName = 'Live')][string]$Organization,
        [Parameter(ParameterSetName = 'Live')][string[]]$Project,
        [Parameter(ParameterSetName = 'Live')][securestring]$AccessToken,
        [Parameter(ParameterSetName = 'Live')][securestring]$Pat,
        [Parameter(ParameterSetName = 'Live')][string]$SaveContextPath,
        [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$ContextPath,
        [string]$ConfigPath,
        [string]$BaselinePath,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 16)][int]$ThrottleLimit = 4,
        [string[]]$CheckPath = $script:CheckRoot
    )

    $catalog = @(Import-AdoScopeCheck -Path $CheckPath)
    $config = Import-AdoScopeConfig -Path $ConfigPath -Check $catalog
    $checks = @($catalog | Where-Object { $_.Id -notin $config.Disabled })
    foreach ($check in $checks) { if ($config.Severity[$check.Id]) { $check.Severity = $config.Severity[$check.Id] } }
    $contextParameters = @{}
    foreach ($name in 'Organization', 'Project', 'AccessToken', 'Pat', 'SaveContextPath', 'ContextPath', 'ThrottleLimit') {
        if ($PSBoundParameters.ContainsKey($name)) { $contextParameters[$name] = $PSBoundParameters[$name] }
    }
    $context = Get-AdoScopeAuditContext @contextParameters -Config $config -Check $checks
    $result = Invoke-AdoScopeCheck -Check $checks -Context $context -Parameters $config.Parameters
    New-AdoScopeReport -Catalog $catalog -Check $checks -Config $config -Context $context -Result $result -BaselinePath $BaselinePath
}

function Get-AdoScopeAuditContext {
    [CmdletBinding(DefaultParameterSetName = 'Live')]
    param(
        [Parameter(ParameterSetName = 'Live')][string]$Organization,
        [Parameter(ParameterSetName = 'Live')][string[]]$Project,
        [Parameter(ParameterSetName = 'Live')][securestring]$AccessToken,
        [Parameter(ParameterSetName = 'Live')][securestring]$Pat,
        [Parameter(ParameterSetName = 'Live')][string]$SaveContextPath,
        [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$ContextPath,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable[]]$Check,
        [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 16)][int]$ThrottleLimit = 4
    )

    if ($PSCmdlet.ParameterSetName -eq 'Offline') { return Import-AdoScopeContext -Path $ContextPath }
    $org = if ($Organization) { $Organization } else { $Config.Organization }
    if (-not $org) { throw 'Specify -Organization or set Organization in the config file.' }
    $projects = if ($Project) { $Project } else { $Config.Projects }
    $auth = Resolve-AdoScopeAuth -AccessToken $AccessToken -Pat $Pat
    Write-Verbose "Authenticated with $($auth.Source)."
    $required = @($Check | ForEach-Object { $_.Requires } | Sort-Object -Unique)
    $context = Get-AdoScopeContext -Organization (ConvertTo-AdoScopeOrganization $org) -Auth $auth -Collection $required -Project $projects -ThrottleLimit $ThrottleLimit
    if ($SaveContextPath) { $context | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $SaveContextPath -Encoding utf8NoBOM }
    $context
}

function New-AdoScopeReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory report object only; no system state changes.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable[]]$Catalog,
        [Parameter(Mandatory)][hashtable[]]$Check,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][pscustomobject]$Result,
        [string]$BaselinePath
    )

    $disabled = @($Catalog | Where-Object { $_.Id -in $Config.Disabled } | ForEach-Object { [pscustomobject]@{ CheckId = $_.Id; Status = 'Disabled'; Message = 'Disabled in configuration.' } })
    [pscustomobject]@{
        PSTypeName   = 'AdoScope.Report'; Tool = 'adoscope'; Version = $MyInvocation.MyCommand.Module.Version.ToString()
        Organization = $Context.Organization; GeneratedAt = [datetime]::UtcNow.ToString('o')
        Collections  = @($Context.Collections.Keys | Sort-Object | ForEach-Object { $collection = $Context.Collections[$_]; [pscustomobject]@{ Name = $_; Status = $collection.Status; Count = @($collection.Items).Count; Error = $collection.Error } })
        Rules        = @($Check | ForEach-Object { New-AdoScopeReportRule -Check $_ -Override $Config.Parameters[$_.Id] })
        Checks       = @($Result.Checks) + $disabled; Findings = $Result.Findings
        Suppressions = @(Resolve-AdoScopeSuppression -Finding $Result.Findings -Suppression $Config.Suppressions)
        Baseline     = if ($BaselinePath) { Resolve-AdoScopeBaseline -Finding @($Result.Findings) -Path $BaselinePath -Organization $Context.Organization } else { $null }
    }
}

function New-AdoScopeReportRule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory rule object only; no system state changes.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Check, [AllowNull()][hashtable]$Override)

    $parameters = $Check.Parameters.Clone()
    if ($Override) { foreach ($key in $Override.Keys) { $parameters[$key] = $Override[$key] } }
    [pscustomobject]@{ Id = $Check.Id; Title = $Check.Title; Category = $Check.Category; Severity = $Check.Severity; Rationale = $Check.Rationale; Remediation = $Check.Remediation; Parameters = $parameters }
}

function Write-AdoScopeReportOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Report, [string]$JsonPath, [string]$SarifPath, [string]$HtmlPath, [switch]$Quiet)

    if ($JsonPath) { Set-Content -LiteralPath $JsonPath -Value (ConvertTo-AdoScopeJsonReport -Report $Report) -Encoding utf8NoBOM }
    if ($SarifPath) { Set-Content -LiteralPath $SarifPath -Value (ConvertTo-AdoScopeSarifReport -Report $Report) -Encoding utf8NoBOM }
    if ($HtmlPath) { Set-Content -LiteralPath $HtmlPath -Value (ConvertTo-AdoScopeHtmlReport -Report $Report) -Encoding utf8NoBOM }
    if (-not $Quiet) { Show-AdoScopeConsoleReport -Report $Report }
}
