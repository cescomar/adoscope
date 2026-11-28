@{
    Id          = 'SEC009'
    Title       = 'Credential stored as a plain-text variable in a variable group'
    Category    = 'Security'
    Standards   = @('CICD-SEC-6')
    Severity    = 'Critical'
    Rationale   = 'A variable not marked as secret is shown in clear text in the UI, returned by the REST API to anyone who can read the variable group, and printed unmasked in pipeline logs. A credential stored this way must be considered leaked.'
    Remediation = 'Revoke and rotate the credential now. Store the new one as a secret variable (lock icon) or, better, in Azure Key Vault linked to the variable group; prefer workload identity federation where the target supports it.'
    # Name hints catch credentials whose value pattern is unknown; values are never stored by the collector.
    # Exclusions drop names that point to a credential rather than hold it (TokenEndpoint, PasswordPolicyUrl).
    Parameters  = @{
        namePatterns   = @('*pat', '*pat_*', '*password*', '*passwd*', '*pwd*', '*secret*', '*token*', '*apikey*', '*api_key*', '*connectionstring*', '*privatekey*')
        nameExclusions = @('*url', '*uri', '*endpoint', '*id', '*name', '*path', '*type', '*scope', '*expiry', '*expiration', '*length', '*header', '*audience', '*issuer')
    }
    Requires    = @('VariableGroups')
    Test        = {
        param($Context, $Parameters)
        foreach ($group in $Context.Collections.VariableGroups.Items) {
            $exposed = @(Get-AdoScopeExposedVariable -Variable $group['variables'] -NamePattern $Parameters.namePatterns -NameExclusion $Parameters.nameExclusions)
            if (-not $exposed) { continue }
            New-AdoScopeFinding -Project $group['_project']?['name'] -Resource $group.name -ResourceId ([string]$group.id) `
                -Detail "Not marked secret: $($exposed -join '; ')."
        }
    }
}
