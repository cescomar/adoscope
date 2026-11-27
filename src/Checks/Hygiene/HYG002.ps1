@{
    Id          = 'HYG002'
    Title       = 'Repository without recent commits'
    Category    = 'Hygiene'
    Severity    = 'Low'
    Rationale   = 'Abandoned repositories keep their permissions, service hooks and pipeline triggers, still show up in code search and audits, and nobody patches their dependencies.'
    Remediation = 'Confirm with the owner, then disable the repository (Repositories > the repository > Settings > Disable repository) to make it read-only, or delete it if it is no longer needed.'
    Parameters  = @{ days = 180 }
    Requires    = @('RepositoryActivity')
    Test        = {
        param($Context, $Parameters)
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($repo in $Context.Collections.RepositoryActivity.Items) {
            if (-not $repo['lastCommitDate']) { continue }
            $days = [int]($now - ([datetime]$repo.lastCommitDate).ToUniversalTime()).TotalDays
            if ($days -lt $Parameters.days) { continue }
            New-AdoScopeFinding -Project $repo['_project']?['name'] -Resource $repo.name -ResourceId $repo.id `
                -Detail "Last commit on '$($repo['defaultBranch'])' was $days days ago; threshold $($Parameters.days)."
        }
    }
}
