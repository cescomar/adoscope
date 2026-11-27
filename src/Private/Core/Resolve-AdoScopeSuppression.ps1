function Resolve-AdoScopeSuppression {
    <#
    .SYNOPSIS
        Marks findings covered by an active suppression (Suppressed, SuppressionReason) and
        returns one status per suppression: Active, Expired (valid through its Expires day,
        then ignored) or Unmatched (nothing to suppress: the issue is fixed or the entry is wrong).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Finding,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable[]]$Suppression,
        [datetime]$Today = [datetime]::UtcNow.Date
    )

    foreach ($s in $Suppression) {
        $matched = @()
        $status = 'Expired'
        if ($Today -le $s.Expires) {
            $matched = @($Finding | Where-Object {
                    $_.CheckId -eq $s.Check -and (
                        ($s['Fingerprint'] -and $_.Fingerprint -eq $s['Fingerprint']) -or
                        ($s['ResourceId'] -and $_.ResourceId -eq $s['ResourceId'] -and (-not $s['Project'] -or $_.Project -eq $s['Project'])))
                })
            foreach ($f in $matched) {
                $f.Suppressed = $true
                $f.SuppressionReason = $s.Reason
            }
            $status = if ($matched) { 'Active' } else { 'Unmatched' }
        }
        [pscustomobject]@{
            Check   = $s.Check
            Target  = if ($s['Fingerprint']) { $s['Fingerprint'] } else { (@($s['Project'], $s['ResourceId']) | Where-Object { $_ }) -join '/' }
            Reason  = $s.Reason
            Expires = $s.Expires.ToString('yyyy-MM-dd')
            Status  = $status
            Matched = $matched.Count
        }
    }
}
