function ConvertTo-AdoScopeJsonReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report
    )

    $Report | Select-Object Tool, SchemaVersion, Version, Organization, GeneratedAt, Scope, Collections, Rules, Checks, Suppressions, Baseline, Findings |
        ConvertTo-Json -Depth 10
}
