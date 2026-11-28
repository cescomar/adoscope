function Get-AdoScopeExposedVariable {
    <#
    .SYNOPSIS
        Non-secret variables that hold or are named like a credential, as sorted
        "<name> (<reason>)" strings. Input is a ConvertTo-AdoScopeVariableSummary result
        (no values). Shared by SEC009 (variable groups) and SEC011 (pipeline definitions).
        The value always wins; a name only counts when it does not describe *where* or
        *which* credential (TokenEndpoint, PasswordPolicyUrl, ClientSecretId).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Variable,
        [Parameter(Mandatory)][string[]]$NamePattern,
        [string[]]$NameExclusion = @()
    )

    if ($Variable -isnot [hashtable]) { return }
    $exposed = foreach ($name in $Variable.Keys) {
        if ($Variable[$name]?['isSecret'] -eq $true) { continue }
        if ($Variable[$name]?['_valueLooksLikeCredential'] -eq $true) { "$name (value matches a credential format)"; continue }
        $byName = @($NamePattern | Where-Object { $name -like $_ }).Count -and -not @($NameExclusion | Where-Object { $name -like $_ }).Count
        if ($byName) { "$name (name suggests a credential)" }
    }
    $exposed | Sort-Object
}
