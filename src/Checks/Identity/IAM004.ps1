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
        foreach ($oversized in Get-AdoScopeOversizedAdminGroup -Group @($Context.Collections.AdminGroups.Items) -Scope project -MaxMembers $Parameters.maxMembers) {
            New-AdoScopeFinding -Project $oversized.Group['project'] -Resource $oversized.Group.principalName -ResourceId $oversized.Group.descriptor -Detail $oversized.Detail
        }
    }
}
