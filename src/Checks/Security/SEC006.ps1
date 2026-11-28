@{
    Id          = 'SEC006'
    Title       = 'Pull requests from forks get secrets or a full-access token'
    Category    = 'Security'
    Standards   = @('CICD-SEC-4')
    Severity    = 'High'
    Rationale   = 'Anyone can open a pull request from a fork. If those builds receive pipeline secrets or a job token with full access, the author of the pull request can change the pipeline to print the secrets or act on the organization.'
    Remediation = 'In the pipeline triggers, turn off "Make secrets available to builds of forks" and "Make fork builds have the same permissions as regular builds". Better: in Organization/Project settings > Pipelines > Settings, limit building pull requests from forked GitHub repositories to "Securely build" or disable it.'
    Requires    = @('BuildDefinitions', 'BuildGeneralSettings')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $settingsByProject = @{}
        foreach ($s in $Context.Collections.BuildGeneralSettings.Items) { $settingsByProject[[string]$s['_project']?['name']] = $s }
        foreach ($definition in $Context.Collections.BuildDefinitions.Items) {
            $s = $settingsByProject[[string]$definition['project']?['name']]
            $protected = $s -and $s['forkProtectionEnabled'] -eq $true
            if ($protected -and $s['buildsEnabledForForks'] -eq $false) { continue }   # fork builds disabled
            $exposed = foreach ($trigger in @($definition['triggers'] | Where-Object { $_ -is [hashtable] })) {
                $forks = $trigger['forks']
                if ($trigger['triggerType'] -ne 'pullRequest' -or $forks -isnot [hashtable] -or $forks['enabled'] -ne $true) { continue }
                if ($forks['allowSecrets'] -eq $true -and -not ($protected -and $s['enforceNoAccessToSecretsFromForks'] -eq $true)) { 'secrets' }
                if ($forks['allowFullAccessToken'] -eq $true -and -not ($protected -and $s['enforceJobAuthScopeForForks'] -eq $true)) { 'full-access token' }
            }
            if (-not $exposed) { continue }
            New-AdoScopeFinding -Project $definition['project']?['name'] -Resource $definition.name -ResourceId ([string]$definition.id) `
                -Detail "Fork pull request builds receive: $(@($exposed | Sort-Object -Unique) -join ', ')."
        }
    }
}
