@{
    Id          = 'SEC005'
    Title       = 'Pipeline security settings disabled'
    Category    = 'Security'
    Severity    = 'High'
    Rationale   = 'These settings limit what a pipeline job token can reach and what a queue-time user can inject. With them off, one compromised pipeline can read or change repositories and resources across the organization.'
    Remediation = 'Enable the listed settings in Organization settings > Pipelines > Settings (enforced for every project) or, if not enforced there, in Project settings > Pipelines > Settings.'
    # Effective values per project; org-level enforcement is already reflected by the API.
    Parameters  = @{
        required = @('enforceJobAuthScope', 'enforceReferencedRepoScopedToken', 'enforceSettableVar', 'enableShellTasksArgsSanitizing')
    }
    Requires    = @('BuildGeneralSettings')
    Test        = {
        param($Context, $Parameters)
        foreach ($settings in $Context.Collections.BuildGeneralSettings.Items) {
            # Missing keys are unknown, not disabled.
            $off = @($Parameters.required | Where-Object { $settings.ContainsKey($_) -and $settings[$_] -ne $true })
            if (-not $off) { continue }
            New-AdoScopeFinding -Project $settings['_project']?['name'] -Resource 'Pipeline settings' `
                -ResourceId "$($settings['_project']?['id'])/generalsettings" `
                -Detail "Disabled: $($off -join ', ')."
        }
    }
}
