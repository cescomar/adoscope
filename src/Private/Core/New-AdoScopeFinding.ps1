function New-AdoScopeFinding {
    <#
    .SYNOPSIS
        Creates a finding. Called from a check's Test block; the runner fills in
        the check metadata (CheckId, Title, Severity, ...) and the Fingerprint.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory object only; no system state changes.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Resource,
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Project
    )

    [pscustomobject]@{
        PSTypeName        = 'AdoScope.Finding'
        CheckId           = $null
        Title             = $null
        Category          = $null
        Severity          = $null
        Project           = if ($Project) { $Project } else { $null }
        Resource          = $Resource
        ResourceId        = $ResourceId
        Detail            = $Detail
        Rationale         = $null
        Remediation       = $null
        Fingerprint       = $null
        Suppressed        = $false
        SuppressionReason = $null
        InBaseline        = $false   # $true when the same Fingerprint is in the -BaselinePath report
    }
}

function Get-AdoScopeFingerprint {
    <#
    .SYNOPSIS
        Stable identity of a finding: survives renames, distinguishes projects.
        Used for suppressions and SARIF partialFingerprints.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$ResourceId,
        [string]$Project
    )

    $key = ('{0}|{1}|{2}' -f $CheckId, $Project, $ResourceId).ToLowerInvariant()
    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($key))
    [System.Convert]::ToHexString($hash).ToLowerInvariant()
}
