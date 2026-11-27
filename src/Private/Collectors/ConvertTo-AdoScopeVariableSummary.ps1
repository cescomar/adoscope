function ConvertTo-AdoScopeVariableSummary {
    <#
    .SYNOPSIS
        Reduces Azure DevOps variables (variable groups, pipeline definitions) to what checks
        need, WITHOUT VALUES: the API returns non-secret values in clear text, and a saved
        context must never contain credentials. Per variable:
          isSecret, _valueLooksLikeCredential (the value matched a credential pattern)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()][object]$Variable)

    $summary = @{}
    if ($Variable -isnot [hashtable]) { return $summary }
    foreach ($name in $Variable.Keys) {
        $value = [string]$Variable[$name]?['value']
        $summary[$name] = @{
            isSecret                  = $Variable[$name]?['isSecret'] -eq $true
            _valueLooksLikeCredential = [bool]$value -and (Protect-AdoScopeText $value) -ne $value
        }
    }
    $summary
}
