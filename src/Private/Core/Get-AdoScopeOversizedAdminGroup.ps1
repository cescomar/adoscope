function Get-AdoScopeOversizedAdminGroup {
    <#
    .SYNOPSIS
        Admin groups of one scope (organization or project) with more effective members than
        allowed, each with a ready-to-report detail (first 10 names, sorted). Shared by
        IAM001 (organization) and IAM004 (project).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Group,
        [Parameter(Mandatory)][ValidateSet('organization', 'project')][string]$Scope,
        [Parameter(Mandatory)][int]$MaxMembers
    )

    foreach ($g in $Group | Where-Object { $_ -is [hashtable] -and $_['scope'] -eq $Scope }) {
        $members = @($g['members'] | Where-Object { $_ -is [hashtable] })
        if ($members.Count -le $MaxMembers) { continue }
        $names = @($members | ForEach-Object { if ($_['principalName']) { $_.principalName } else { $_.descriptor } } | Sort-Object)
        $more = if ($names.Count -gt 10) { " (+$($names.Count - 10) more)" } else { '' }
        [pscustomobject]@{
            Group  = $g
            Detail = "$($members.Count) members, maximum ${MaxMembers}: $(($names | Select-Object -First 10) -join ', ')$more."
        }
    }
}
