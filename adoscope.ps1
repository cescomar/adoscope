#Requires -Version 7.2
<#
.SYNOPSIS
    Runs adoscope and returns CI-friendly exit codes.

.EXAMPLE
    # GitHub Actions: ./adoscope.ps1 -Organization $env:ADO_ORG -SarifPath results.sarif -Quiet

.EXAMPLE
    # Azure Pipelines: ./adoscope.ps1 -Organization $(adoOrganization) -HtmlPath $(Build.ArtifactStagingDirectory)/adoscope.html -Quiet

.EXAMPLE
    # Adopt the gate on an organization with existing findings: block only new ones.
    ./adoscope.ps1 -Organization fabrikam -BaselinePath ./baseline.json -JsonPath ./report.json
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Live', Position = 0)][string]$Organization,
    [Parameter(ParameterSetName = 'Live')][string[]]$Project,
    [Parameter(ParameterSetName = 'Live')][securestring]$AccessToken,
    [Parameter(ParameterSetName = 'Live')][securestring]$Pat,
    [Parameter(ParameterSetName = 'Live')][string]$SaveContextPath,
    [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 16)][int]$ThrottleLimit = 4,
    [Parameter(Mandatory, ParameterSetName = 'Offline')][string]$ContextPath,
    [string]$ConfigPath,
    [string]$BaselinePath,
    [string[]]$CheckPath,
    [string]$JsonPath,
    [string]$SarifPath,
    [string]$HtmlPath,
    [switch]$Quiet,
    [switch]$PassThru,
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info', 'None')][string]$FailOn = 'High',
    [switch]$AllowIncompleteCoverage
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'adoscope.psd1') -Force
try {
    $invoke = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        if ($name -notin 'FailOn', 'AllowIncompleteCoverage', 'PassThru') { $invoke[$name] = $PSBoundParameters[$name] }
    }
    $invoke['PassThru'] = $true
    $report = Invoke-AdoScope @invoke
}
catch {
    # Credentials are masked by the module's redaction; the rest of the message is needed to act on the failure.
    $message = & (Get-Module adoscope) { param($Text) Protect-AdoScopeText $Text } $_.Exception.Message
    [Console]::Error.WriteLine("adoscope failed: $message")
    exit 3
}
$severities = @('Info', 'Low', 'Medium', 'High', 'Critical')
$threshold = [array]::IndexOf($severities, $FailOn)
# Findings already in the baseline are accepted debt: only new ones fail the build.
$failed = $FailOn -ne 'None' -and @($report.Findings | Where-Object {
        -not $_.Suppressed -and -not $_.InBaseline -and [array]::IndexOf($severities, $_.Severity) -ge $threshold
    }).Count -gt 0
if ($failed) { exit 1 }
if (-not $AllowIncompleteCoverage -and @($report.Checks | Where-Object Status -in 'Partial', 'NotEvaluated', 'Error').Count -gt 0) { exit 2 }
exit 0
