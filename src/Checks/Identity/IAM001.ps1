@{
    Id          = 'IAM001'
    Title       = 'Too many Project Collection Administrators'
    Category    = 'Identity'
    Severity    = 'High'
    Rationale   = 'Project Collection Administrators can change every project, pipeline, service connection, policy and permission in the organization. Each extra member is one more account whose compromise exposes everything, and broad membership makes it hard to tell who approved what.'
    Remediation = 'Keep only a few named owners in Project Collection Administrators. Give others the narrower role they need (Project Administrators, Build Administrators, Endpoint Administrators), and prefer an Entra ID group with access reviews over individual accounts.'
    # Counts people and service principals after expanding nested groups; built-in service identities are excluded.
    Parameters  = @{ maxMembers = 5 }
    Requires    = @('AdminGroups')
    Test        = {
        param($Context, $Parameters)
        foreach ($group in $Context.Collections.AdminGroups.Items | Where-Object { $_['scope'] -eq 'organization' }) {
            $members = @($group['members'] | Where-Object { $_ -is [hashtable] })
            if ($members.Count -le $Parameters.maxMembers) { continue }
            $names = @($members | ForEach-Object { if ($_['principalName']) { $_.principalName } else { $_.descriptor } } | Sort-Object)
            $shown = ($names | Select-Object -First 10) -join ', '
            $more = if ($names.Count -gt 10) { " (+$($names.Count - 10) more)" } else { '' }
            New-AdoScopeFinding -Resource $group.principalName -ResourceId $group.descriptor `
                -Detail "$($members.Count) members, maximum $($Parameters.maxMembers): $shown$more."
        }
    }
}
