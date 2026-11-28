@{
    Id          = 'SEC003'
    Title       = 'Default branch without required reviewers'
    Category    = 'Security'
    Standards   = @('CICD-SEC-1')
    Severity    = 'Medium'
    Rationale   = 'Without a blocking minimum-reviewers policy, anyone with contribute rights can push or merge to the default branch, and pipelines deploy whatever lands there. One compromised account is enough to ship code.'
    Remediation = 'In Project settings > Repositories > Policies (or the branch policies of the default branch), enable "Require a minimum number of reviewers" as a required policy, with at least the configured number of reviewers and without allowing requestors to approve their own changes.'
    Parameters  = @{ minimumApprovers = 1; allowSelfApproval = $false }
    Requires    = @('Repositories', 'Policies')
    Test        = {
        param($Context, $Parameters)
        $reviewerPolicies = @($Context.Collections.Policies.Items | Where-Object {
                $_['type']?['id'] -eq 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' -and $_['isEnabled'] -eq $true -and $_['isBlocking'] -eq $true -and
                [int]($_['settings']?['minimumApproverCount']) -ge $Parameters.minimumApprovers -and
                ($Parameters.allowSelfApproval -or $_['settings']?['creatorVoteCounts'] -ne $true)
            })
        foreach ($repo in $Context.Collections.Repositories.Items) {
            $branch = $repo['defaultBranch']
            if (-not $branch -or $repo['isDisabled'] -eq $true) { continue }   # empty or archived
            # repositoryId = null means every repository of the policy's own project.
            $covered = $reviewerPolicies | Where-Object { $_['_project']?['id'] -eq $repo['project']?['id'] } | Where-Object {
                @($_['settings']?['scope']) | Where-Object { $_ -is [hashtable] } | Where-Object {
                    $scopeRepo = $_['repositoryId']
                    $ref = $_['refName']
                    (-not $scopeRepo -or $scopeRepo -eq $repo.id) -and (
                        -not $ref -or
                        ($_['matchKind'] -eq 'Prefix' -and $branch.StartsWith($ref, [StringComparison]::OrdinalIgnoreCase)) -or
                        ($_['matchKind'] -ne 'Prefix' -and $branch -eq $ref))
                }
            }
            if ($covered) { continue }
            New-AdoScopeFinding -Project $repo['project']?['name'] -Resource $repo.name -ResourceId $repo.id `
                -Detail "Branch '$branch' has no required policy with at least $($Parameters.minimumApprovers) reviewer(s)."
        }
    }
}
