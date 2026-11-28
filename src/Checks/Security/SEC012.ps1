@{
    Id          = 'SEC012'
    Title       = 'Credential stored as a plain-text variable in a classic release'
    Category    = 'Security'
    Severity    = 'Critical'
    Rationale   = 'A release or stage variable not marked as secret is visible in the release editor, returned by the REST API to anyone who can read the release, and printed unmasked in deployment logs. A credential stored this way must be considered leaked.'
    Remediation = 'Revoke and rotate the credential now. Store the new one as a secret variable (lock icon), in a variable group linked to Azure Key Vault, or replace it with a service connection using workload identity federation.'
    Parameters  = @{
        namePatterns   = @('*pat', '*pat_*', '*password*', '*passwd*', '*pwd*', '*secret*', '*token*', '*apikey*', '*api_key*', '*connectionstring*', '*privatekey*')
        nameExclusions = @('*url', '*uri', '*endpoint', '*id', '*name', '*path', '*type', '*scope', '*expiry', '*expiration', '*length', '*header', '*audience', '*issuer')
    }
    Requires    = @('ReleaseDefinitions')
    Test        = {
        param($Context, $Parameters)
        foreach ($definition in $Context.Collections.ReleaseDefinitions.Items) {
            $exposed = @(Get-AdoScopeExposedVariable -Variable $definition['variables'] -NamePattern $Parameters.namePatterns -NameExclusion $Parameters.nameExclusions)
            foreach ($stage in @($definition['environments']) | Where-Object { $_ -is [hashtable] }) {
                $exposed += @(Get-AdoScopeExposedVariable -Variable $stage['variables'] -NamePattern $Parameters.namePatterns -NameExclusion $Parameters.nameExclusions |
                        ForEach-Object { "$_ in stage '$($stage['name'])'" })
            }
            if (-not $exposed) { continue }
            New-AdoScopeFinding -Project $definition['project']?['name'] -Resource $definition.name -ResourceId ([string]$definition.id) `
                -Detail "Not marked secret: $($exposed -join '; ')."
        }
    }
}
