function ConvertTo-AdoScopeJsonReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Report
    )

    $Report | Select-Object Tool, Version, Organization, GeneratedAt, Collections, Rules, Checks, Suppressions, Baseline, Findings |
        ConvertTo-Json -Depth 10
}
