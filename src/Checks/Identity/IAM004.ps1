@{
    Id          = 'IAM004'
    Title       = 'Too many Project Administrators'
    Category    = 'Identity'
    Severity    = 'Medium'
    Rationale   = 'Project Administrators can change pipelines, repositories, branch policies, service connections and permissions of the project, including removing the controls other checks rely on. Broad membership widens the attack surface and blurs accountability.'
    Remediation = 'Reduce Project Administrators to the project owners. Grant contributors the narrower groups they need (Contributors, Build Administrators, Release Administrators), ideally through Entra ID groups with periodic access reviews.'
    Parameters  = @{ maxMembers = 5 }
    Requires    = @('AdminGroups')
    Test        = {
        param($Context, $Parameters)
        foreach ($group in $Context.Collections.AdminGroups.Items | Where-Object { $_['scope'] -eq 'project' }) {
            $members = @($group['members'] | Where-Object { $_ -is [hashtable] })
            if ($members.Count -le $Parameters.maxMembers) { continue }
            $names = @($members | ForEach-Object { if ($_['principalName']) { $_.principalName } else { $_.descriptor } } | Sort-Object)
            $shown = ($names | Select-Object -First 10) -join ', '
            $more = if ($names.Count -gt 10) { " (+$($names.Count - 10) more)" } else { '' }
            New-AdoScopeFinding -Project $group['project'] -Resource $group.principalName -ResourceId $group.descriptor `
                -Detail "$($members.Count) members, maximum $($Parameters.maxMembers): $shown$more."
        }
    }
}
