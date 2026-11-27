function Add-AdoScopeEnrichment {
    <#
    .SYNOPSIS
        Adds data from a secondary call (permissions, checks) to one item. If the call
        fails, only this item is marked: Key = $null and _error explains why. The item
        and its siblings are kept; Get-AdoScopeContext turns _error into a Partial collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Item,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$What,
        [Parameter(Mandatory)][scriptblock]$Value
    )

    try { $Item[$Key] = & $Value }
    catch {
        $Item[$Key] = $null
        $Item._error = "$What of '$($Item['name'])': $(Protect-AdoScopeText $_.Exception.Message)"
    }
}
