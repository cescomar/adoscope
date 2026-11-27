# Synthetic check used by tests only: flags projects whose visibility equals a parameter.
@{
    Id          = 'TST001'
    Title       = 'Project has flagged visibility'
    Category    = 'Test'
    Severity    = 'High'
    Rationale   = 'Test rationale.'
    Remediation = 'Test remediation.'
    Parameters  = @{ visibility = 'public' }
    Requires    = @('Projects')
    Test        = {
        param($Context, $Parameters)
        foreach ($project in $Context.Collections.Projects.Items) {
            if ($project['visibility'] -eq $Parameters.visibility) {
                New-AdoScopeFinding -Project $project.name -Resource $project.name -ResourceId $project.id `
                    -Detail "Visibility is '$($project.visibility)'."
            }
        }
    }
}
