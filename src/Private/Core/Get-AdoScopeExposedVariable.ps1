function Get-AdoScopeExposedVariable {
    <#
    .SYNOPSIS
        Non-secret variables that hold or are named like a credential, as sorted
        "<name> (<reason>)" strings. Input is a ConvertTo-AdoScopeVariableSummary result
        (no values). Shared by SEC009 (variable groups) and SEC011 (pipeline definitions).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()][object]$Variable,
        [Parameter(Mandatory)][string[]]$NamePattern
    )

    if ($Variable -isnot [hashtable]) { return }
    $exposed = foreach ($name in $Variable.Keys) {
        if ($Variable[$name]?['isSecret'] -eq $true) { continue }
        if ($Variable[$name]?['_valueLooksLikeCredential'] -eq $true) { "$name (value matches a credential format)"; continue }
        if (@($NamePattern | Where-Object { $name -like $_ }).Count) { "$name (name suggests a credential)" }
    }
    $exposed | Sort-Object
}
