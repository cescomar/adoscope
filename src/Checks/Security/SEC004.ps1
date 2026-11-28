@{
    Id          = 'SEC004'
    Title       = 'Public project'
    Category    = 'Security'
    Standards   = @('CICD-SEC-7')
    Severity    = 'Medium'
    Rationale   = 'Anyone on the internet can read the code, work items, pipeline logs and artifacts of a public project. Logs and build outputs often leak internal hostnames, configuration and occasionally secrets.'
    Remediation = 'If the project is not meant to be open source, set Project settings > Overview > Visibility to Private. If it is, review pipeline logs and artifacts for internal data and disable "Allow public projects" at organization level for everything else.'
    Requires    = @('Projects')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($project in $Context.Collections.Projects.Items) {
            if ($project['visibility'] -ne 'public') { continue }
            New-AdoScopeFinding -Project $project.name -Resource $project.name -ResourceId $project.id -Detail "Project '$($project.name)' is public."
        }
    }
}
