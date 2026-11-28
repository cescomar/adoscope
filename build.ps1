#Requires -Version 7.2
<#
.SYNOPSIS
    Runs PSScriptAnalyzer (default rules) and the Pester suite. Same entry point locally and in CI.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module PSScriptAnalyzer
Import-Module Pester -MinimumVersion 5.5 -MaximumVersion 5.99.99

$issues = @(Invoke-ScriptAnalyzer -Path $PSScriptRoot -Recurse)
if ($issues) {
    $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String | Write-Output
    throw "PSScriptAnalyzer reported $($issues.Count) issue(s)."
}
Write-Output 'PSScriptAnalyzer: clean'

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'tests'
$config.Run.Throw = $true
$config.Output.Verbosity = 'Detailed'
$config.Run.PassThru = $true
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = @((Join-Path $PSScriptRoot 'src'), (Join-Path $PSScriptRoot 'adoscope.psm1'))
$config.CodeCoverage.OutputPath = Join-Path ([IO.Path]::GetTempPath()) 'adoscope-coverage.xml'
$result = Invoke-Pester -Configuration $config

# Pester only reports coverage; this makes a drop below the floor fail the build.
# Measured 89.7% at v0.2.0; uncovered lines are mostly collectors, which the live lab exercises.
$minimumCoverage = 85
$coverage = [math]::Round($result.CodeCoverage.CoveragePercent, 1)
if ($coverage -lt $minimumCoverage) { throw "Code coverage $coverage% is below the $minimumCoverage% floor." }
Write-Output "Code coverage: $coverage% (floor $minimumCoverage%)"
