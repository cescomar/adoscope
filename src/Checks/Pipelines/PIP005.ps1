@{
    Id          = 'PIP005'
    Title       = 'Release creator can approve their own production deployment'
    Category    = 'Pipelines'
    Standards   = @('CICD-SEC-1')
    Severity    = 'Medium'
    Rationale   = 'When the person who creates a release may also approve it, one account is enough to push a change to production: the approval becomes a formality and separation of duties is lost.'
    Remediation = 'In the pre-deployment conditions of the stage, open Approval policies and enable "The user requesting a release or deployment should not approve it". Use an approver group with at least two members.'
    Parameters  = @{ productionPatterns = @('prod', 'prod-*', 'prod_*', '*-prod', '*_prod', '*-prod-*', '*production*', '*produzione*', 'prd', 'prd-*', '*-prd', 'live') }
    Requires    = @('ReleaseDefinitions')
    Test        = {
        param($Context, $Parameters)
        foreach ($definition in $Context.Collections.ReleaseDefinitions.Items) {
            if ($definition['_error']) { continue }
            foreach ($stage in @($definition['environments']) | Where-Object { $_ -is [hashtable] }) {
                $name = [string]$stage['name']
                if (-not @($Parameters.productionPatterns | Where-Object { $name -like $_ })) { continue }
                # Only meaningful when someone must approve; PIP004 covers stages without manual approval.
                $manual = @($stage['approvals'] | Where-Object { $_ -is [hashtable] -and $_['isAutomated'] -ne $true })
                if (-not $manual -or $stage['releaseCreatorCanBeApprover'] -ne $true) { continue }
                New-AdoScopeFinding -Project $definition['project']?['name'] -Resource "$($definition.name)/$name" -ResourceId "$($definition.id)/$($stage['id'])" `
                    -Detail "Stage '$name' of release '$($definition.name)' lets the release creator approve it."
            }
        }
    }
}
