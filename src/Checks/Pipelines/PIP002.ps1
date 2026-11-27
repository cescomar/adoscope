@{
    Id          = 'PIP002'
    Title       = 'Production environment without Required template check'
    Category    = 'Pipelines'
    Severity    = 'Medium'
    Rationale   = 'Approvals check who deploys, not how. Without a Required template check, a pipeline can deploy to production with arbitrary steps, skipping the security scans, tests and controls built into the approved template.'
    Remediation = 'In Pipelines > Environments > the environment > Approvals and checks, add "Required template" pointing to your approved pipeline template, so only pipelines that extend it can deploy.'
    Parameters  = @{ productionPatterns = @('prod', 'prod-*', 'prod_*', '*-prod', '*_prod', '*-prod-*', '*production*', '*produzione*', 'prd', 'prd-*', '*-prd', 'live') }
    Requires    = @('Environments')
    Test        = {
        param($Context, $Parameters)
        # Required template = check type ExtendsCheck (id 4020e66e-b0f3-47e1-bc88-48f3cc59b5f3).
        foreach ($environment in $Context.Collections.Environments.Items) {
            $name = [string]$environment['name']
            if (-not @($Parameters.productionPatterns | Where-Object { $name -like $_ })) { continue }
            if ($environment['_error']) { continue }   # checks unreadable: unknown, not missing (collection is Partial)
            $template = @($environment['_checks'] | Where-Object {
                    $_ -is [hashtable] -and $_['isDisabled'] -ne $true -and
                    ($_['type']?['name'] -eq 'ExtendsCheck' -or $_['type']?['id'] -eq '4020e66e-b0f3-47e1-bc88-48f3cc59b5f3')
                })
            if ($template) { continue }
            New-AdoScopeFinding -Project $environment['_project']?['name'] -Resource $name -ResourceId ([string]$environment.id) `
                -Detail "Environment '$name' looks like production and does not require an approved pipeline template."
        }
    }
}
