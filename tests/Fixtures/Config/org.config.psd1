# Used with tests/Fixtures/Context/org.json. Synthetic values only.
@{
    Organization = 'contoso-sample'
    Checks       = @{
        Disabled   = @('SEC007')
        # web-stale (151 days) drops out, api-never-old (182 days) stays.
        Parameters = @{ HYG001 = @{ days = 160 } }
        Severity   = @{ PIP003 = 'Medium' }
    }
    Suppressions = @(
        # Active: matches api-generic in project api.
        @{ Check = 'SEC001'; Project = 'api'; ResourceId = '00000000-0000-0000-0000-0000000000e6'; Reason = 'Accepted risk: read-only mirror credential.'; Expires = '2099-12-31' }
        # Expired: web-azure-legacy is reported again.
        @{ Check = 'SEC002'; ResourceId = '00000000-0000-0000-0000-0000000000e2'; Reason = 'Migration to WIF planned.'; Expires = '2020-01-01' }
        # Unmatched: nothing with this id.
        @{ Check = 'PIP003'; ResourceId = '999'; Reason = 'Pipeline already removed.'; Expires = '2099-12-31' }
    )
}
