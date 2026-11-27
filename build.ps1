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
Invoke-Pester -Configuration $config
