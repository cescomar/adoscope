@{
    Id          = 'PIP001'
    Title       = 'Production environment without approvals or checks'
    Category    = 'Pipelines'
    Standards   = @('CICD-SEC-1')
    Severity    = 'High'
    Rationale   = 'Without checks on the environment, any pipeline that can target it deploys straight to production: no approval, no branch control, no required template. A mistaken or malicious change reaches users unreviewed.'
    Remediation = 'In Pipelines > Environments > the environment > Approvals and checks, add an Approval and Branch control (only the default branch); consider Required template so deployments go through the approved pipeline template.'
    # Names compared case-insensitively with -like. Tune to your naming convention.
    Parameters  = @{ productionPatterns = @('prod', 'prod-*', 'prod_*', '*-prod', '*_prod', '*-prod-*', '*production*', '*produzione*', 'prd', 'prd-*', '*-prd', 'live') }
    Requires    = @('Environments')
    Test        = {
        param($Context, $Parameters)
        foreach ($environment in $Context.Collections.Environments.Items) {
            $name = [string]$environment['name']
            if (-not @($Parameters.productionPatterns | Where-Object { $name -like $_ })) { continue }
            if ($environment['_error']) { continue }   # checks unreadable: unknown, not missing (collection is Partial)
            $active = @($environment['_checks'] | Where-Object { $_ -is [hashtable] -and $_['isDisabled'] -ne $true })
            if ($active) { continue }
            New-AdoScopeFinding -Project $environment['_project']?['name'] -Resource $name -ResourceId ([string]$environment.id) `
                -Detail "Environment '$name' looks like production and has no approvals or checks."
        }
    }
}
