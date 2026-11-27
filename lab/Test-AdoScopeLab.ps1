#Requires -Version 7.2
<#
.SYNOPSIS
    Verifies that adoscope still finds exactly the expected issues in the live lab project.

.DESCRIPTION
    Runs adoscope (read-only) on the lab project created by Initialize-AdoScopeLab.ps1 and
    compares its findings with lab/expected-findings.json ("<CheckId> <Resource>" per entry).
    A missing finding means a check stopped detecting something (often an Azure DevOps API
    change); an unexpected one means a false positive or a changed lab. Both fail.
    Only findings of the lab project are compared; organization-wide findings are ignored.

    Exit codes: 0 match; 1 difference; 3 the audit itself failed.

.EXAMPLE
    $env:AZURE_DEVOPS_EXT_PAT = '<read-only PAT>'; ./lab/Test-AdoScopeLab.ps1 -Organization fabrikam
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Organization,
    [string]$ProjectName = 'adoscope-lab',
    [string]$ExpectedPath = (Join-Path $PSScriptRoot 'expected-findings.json')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../adoscope.psd1') -Force
try {
    $report = Invoke-AdoScope -Organization $Organization -Project $ProjectName -Quiet -PassThru -WarningAction SilentlyContinue
}
catch {
    [Console]::Error.WriteLine("lab audit failed: $($_.Exception.Message)")
    exit 3
}

$expected = @(Get-Content -LiteralPath $ExpectedPath -Raw | ConvertFrom-Json | Sort-Object)
$actual = @($report.Findings | Where-Object Project -eq $ProjectName | ForEach-Object { "$($_.CheckId) $($_.Resource)" } | Sort-Object -Unique)
$missing = @($expected | Where-Object { $_ -notin $actual })
$unexpected = @($actual | Where-Object { $_ -notin $expected })

foreach ($check in $report.Checks | Where-Object Status -notin 'Evaluated', 'Disabled') {
    Write-Output "coverage: [$($check.CheckId)] $($check.Status): $($check.Message)"
}
foreach ($line in $missing) { Write-Output "MISSING    $line" }
foreach ($line in $unexpected) { Write-Output "UNEXPECTED $line" }
if ($missing -or $unexpected) {
    Write-Output "lab drift: $($missing.Count) missing, $($unexpected.Count) unexpected (expected $($expected.Count))."
    exit 1
}
Write-Output "lab ok: all $($expected.Count) expected findings, nothing else."
exit 0
