# Synthetic check used by tests only: requires a collection the sample context marks as Forbidden.
@{
    Id          = 'TST002'
    Title       = 'Repository check'
    Category    = 'Test'
    Severity    = 'Medium'
    Rationale   = 'Test rationale.'
    Remediation = 'Test remediation.'
    Requires    = @('Repositories')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($repo in $Context.Collections.Repositories.Items) {
            New-AdoScopeFinding -Resource $repo.name -ResourceId $repo.id -Detail 'Always flagged.'
        }
    }
}
