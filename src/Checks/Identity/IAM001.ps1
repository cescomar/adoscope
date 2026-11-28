@{
    Id          = 'IAM001'
    Title       = 'Too many Project Collection Administrators'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-2')
    Severity    = 'High'
    Rationale   = 'Project Collection Administrators can change every project, pipeline, service connection, policy and permission in the organization. Each extra member is one more account whose compromise exposes everything, and broad membership makes it hard to tell who approved what.'
    Remediation = 'Keep only a few named owners in Project Collection Administrators. Give others the narrower role they need (Project Administrators, Build Administrators, Endpoint Administrators), and prefer an Entra ID group with access reviews over individual accounts.'
    # Counts people and service principals after expanding nested groups; built-in service identities are excluded.
    Parameters  = @{ maxMembers = 5 }
    Requires    = @('AdminGroups')
    Test        = {
        param($Context, $Parameters)
        foreach ($oversized in Get-AdoScopeOversizedAdminGroup -Group @($Context.Collections.AdminGroups.Items) -Scope organization -MaxMembers $Parameters.maxMembers) {
            New-AdoScopeFinding -Resource $oversized.Group.principalName -ResourceId $oversized.Group.descriptor -Detail $oversized.Detail
        }
    }
}
