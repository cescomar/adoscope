@{
    Id          = 'PIP004'
    Title       = 'Production stage of a classic release without approval'
    Category    = 'Pipelines'
    Standards   = @('CICD-SEC-1')
    Severity    = 'High'
    Rationale   = 'A classic release stage with only automatic approval and no gates deploys to production as soon as a release is created or the previous stage succeeds. A mistaken or malicious build reaches users without anyone reviewing it.'
    Remediation = 'In the release pipeline, open the pre-deployment conditions of the stage and add at least one manual approver (a group, not one person), and consider gates such as Azure Monitor alerts. Better: move the release to a YAML pipeline that deploys to an environment with approvals and checks.'
    Parameters  = @{ productionPatterns = @('prod', 'prod-*', 'prod_*', '*-prod', '*_prod', '*-prod-*', '*production*', '*produzione*', 'prd', 'prd-*', '*-prd', 'live') }
    Requires    = @('ReleaseDefinitions')
    Test        = {
        param($Context, $Parameters)
        foreach ($definition in $Context.Collections.ReleaseDefinitions.Items) {
            if ($definition['_error']) { continue }   # stages unreadable: unknown, not unprotected
            foreach ($stage in @($definition['environments']) | Where-Object { $_ -is [hashtable] }) {
                $name = [string]$stage['name']
                if (-not @($Parameters.productionPatterns | Where-Object { $name -like $_ })) { continue }
                $manual = @($stage['approvals'] | Where-Object { $_ -is [hashtable] -and $_['isAutomated'] -ne $true })
                if ($manual -or [int]$stage['gates'] -gt 0) { continue }
                New-AdoScopeFinding -Project $definition['project']?['name'] -Resource "$($definition.name)/$name" -ResourceId "$($definition.id)/$($stage['id'])" `
                    -Detail "Stage '$name' of release '$($definition.name)' deploys without manual approval or gates."
            }
        }
    }
}
