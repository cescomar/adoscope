@{
    Id          = 'SEC011'
    Title       = 'Credential stored as a plain-text variable in a pipeline definition'
    Category    = 'Security'
    Severity    = 'Critical'
    Rationale   = 'A pipeline variable not marked as secret is visible in the pipeline editor, returned by the REST API to anyone who can read the pipeline, and printed unmasked in logs. A credential stored this way must be considered leaked.'
    Remediation = 'Revoke and rotate the credential now. Store the new one as a secret pipeline variable (lock icon), in a variable group linked to Azure Key Vault, or replace it with a service connection using workload identity federation.'
    # Only variables defined in the pipeline settings (UI); variables written in the YAML file itself are not read.
    Parameters  = @{ namePatterns = @('*pat', '*pat_*', '*password*', '*passwd*', '*pwd*', '*secret*', '*token*', '*apikey*', '*api_key*', '*connectionstring*', '*privatekey*') }
    Requires    = @('BuildDefinitions')
    Test        = {
        param($Context, $Parameters)
        foreach ($definition in $Context.Collections.BuildDefinitions.Items) {
            $exposed = @(Get-AdoScopeExposedVariable -Variable $definition['variables'] -NamePattern $Parameters.namePatterns)
            if (-not $exposed) { continue }
            New-AdoScopeFinding -Project $definition['project']?['name'] -Resource $definition.name -ResourceId ([string]$definition.id) `
                -Detail "Not marked secret: $($exposed -join '; ')."
        }
    }
}
