function Protect-AdoScopeText {
    <#
    .SYNOPSIS
        Redacts anything that looks like a credential before text reaches a log,
        warning, exception or report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text
    )

    if (-not $Text) { return $Text }
    $patterns = @(
        '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+'   # Authorization header values
        '\beyJ[\w-]+\.[\w-]+\.[\w-]*'                   # JWT (Entra access tokens)
        '\b[A-Za-z0-9]{84}\b'                           # Azure DevOps PAT (current format)
        '\b[a-z2-7]{52}\b'                              # Azure DevOps PAT (legacy base32)
        '\bgh[pousr]_[A-Za-z0-9]{36,}\b'                # GitHub tokens
        '\bAKIA[0-9A-Z]{16}\b'                          # AWS access key id
        '[A-Za-z0-9+/]{86}=='                           # Azure storage account key
        '(?i)\b(password|pwd|accountkey|sharedaccesskey|clientsecret)\s*=\s*[^;\s"'']+'   # connection strings
    )
    foreach ($pattern in $patterns) { $Text = $Text -replace $pattern, '[REDACTED]' }
    $Text
}
