BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
    # Every built-in check against one synthetic org with compliant, non-compliant and
    # incomplete resources; also proves the catalog loads.
    $script:result = InModuleScope adoscope -Parameters @{ Root = (Join-Path $PSScriptRoot '../..') } {
        param($Root)
        $context = Import-AdoScopeContext -Path (Join-Path $Root 'tests/Fixtures/Context/org.json')
        Invoke-AdoScopeCheck -Check @(Import-AdoScopeCheck -Path (Join-Path $Root 'src/Checks')) -Context $context
    }
}

Describe 'Built-in checks' {
    It '<Id> flags exactly the non-compliant resources' -ForEach @(
        @{ Id = 'SEC001'; Expected = @('api-generic', 'web-azure-secret') }
        @{ Id = 'SEC002'; Expected = @('web-azure-legacy', 'web-azure-secret') }   # shared connection reported once
        @{ Id = 'SEC003'; Expected = @('api-gw', 'api-svc', 'web-lib') }           # not blocking / self-approval / other project's policy
        @{ Id = 'SEC004'; Expected = @('data') }
        @{ Id = 'SEC005'; Expected = @('Pipeline settings') }
        @{ Id = 'SEC006'; Expected = @('api-never-old', 'web-ci') }
        @{ Id = 'SEC007'; Expected = @('web-azure-cert') }
        @{ Id = 'SEC008'; Expected = @('api-kv', 'web-secrets') }                 # open group without secrets is fine
        @{ Id = 'SEC009'; Expected = @('api-config') }
        @{ Id = 'SEC010'; Expected = @('signing.pfx') }
        @{ Id = 'SEC011'; Expected = @('api-never-new', 'web-ci') }              # secret NugetKey and plain BuildConfig not flagged
        @{ Id = 'SEC012'; Expected = @('web-release') }                          # definition and stage variables; secret and TokenUrl skipped
        @{ Id = 'SEC013'; Expected = @('Auto Merge') }                           # read-only scopes, disabled, built-in and trusted skipped
        @{ Id = 'PIP001'; Expected = @('live', 'production') }                  # disabled check does not count; unreadable checks (prod-unreadable) are not "missing"
        @{ Id = 'PIP002'; Expected = @('live', 'prod-eu', 'production') }
        @{ Id = 'PIP003'; Expected = @('web-classic') }
        @{ Id = 'PIP004'; Expected = @('web-release/Production') }               # Dev is not production; live has gates; unreadable definition skipped
        @{ Id = 'PIP005'; Expected = @('api-release/prod-eu') }                  # prod-us forbids self-approval
        @{ Id = 'AGT001'; Expected = @() }                                      # no trust groups configured
        @{ Id = 'AGT002'; Expected = @('shared-linux/linux-01', 'shared-linux/linux-02') }   # v3 and v4 below 5.0.0; v5 ok; hosted and elastic skipped
        @{ Id = 'AGT003'; Expected = @('shared-linux/linux-02') }
        @{ Id = 'HYG001'; Expected = @('api-never-old', 'web-stale') }
        @{ Id = 'HYG002'; Expected = @('web-lib') }
        @{ Id = 'CST001'; Expected = @('bob@contoso.example', 'carol@contoso.example') }   # msdn and stakeholder skipped
        @{ Id = 'REL001'; Expected = @('web-ci') }
        @{ Id = 'IAM001'; Expected = @('[contoso-sample]\Project Collection Administrators') }   # 6 > 5, nested member counted
        @{ Id = 'IAM002'; Expected = @('bob@contoso.example', 'carol@contoso.example') }        # service principal without license record skipped
        @{ Id = 'IAM003'; Expected = @('dan@partner.example') }                                 # one finding across two groups
        @{ Id = 'IAM004'; Expected = @('[api]\Project Administrators') }
        @{ Id = 'IAM005'; Expected = @('contoso-sample') }
        @{ Id = 'IAM006'; Expected = @('alice@contoso.example/deploy-script') }  # expired, revoked and unreadable tokens skipped
        @{ Id = 'IAM007'; Expected = @('alice@contoso.example/code-read') }      # 365 days; deploy-script is 60
        @{ Id = 'IAM008'; Expected = @('alice@contoso.example/code-read') }
    ) {
        ($result.Checks | Where-Object CheckId -eq $Id).Status | Should -Be 'Evaluated'
        (@($result.Findings | Where-Object CheckId -eq $Id | ForEach-Object Resource | Sort-Object) -join ', ') | Should -Be ($Expected -join ', ')
    }

    It 'SEC005 names the disabled settings and only the project that has them off' {
        $f = $result.Findings | Where-Object CheckId -eq 'SEC005'
        $f.Project | Should -Be 'api'
        $f.Detail | Should -Be 'Disabled: enforceJobAuthScope, enforceSettableVar.'
    }

    It 'identity details name the evidence: <Id>' -ForEach @(
        @{ Id = 'IAM002'; Resource = 'carol@contoso.example'; Detail = 'Never signed in (added 137 days ago); threshold 90 days. Administrator in: [contoso-sample]\Project Collection Administrators.' }
        @{ Id = 'IAM002'; Resource = 'bob@contoso.example'; Detail = 'Last access 151 days ago; threshold 90 days. Administrator in: [contoso-sample]\Project Collection Administrators.' }
        @{ Id = 'IAM003'; Resource = 'dan@partner.example'; Detail = 'Guest account is administrator in: [contoso-sample]\Project Collection Administrators, [web]\Project Administrators.' }
        @{ Id = 'IAM005'; Resource = 'contoso-sample'; Detail = '1 administrator(s) sign in with a personal Microsoft account; the organization is not backed by Entra ID.' }
        @{ Id = 'IAM006'; Resource = 'alice@contoso.example/deploy-script'; Detail = "Token 'deploy-script' of alice@contoso.example has full access; valid until 2026-06-30." }
        @{ Id = 'IAM007'; Resource = 'alice@contoso.example/code-read'; Detail = "Token 'code-read' of alice@contoso.example is valid for 365 days (until 2027-01-01); maximum 90." }
    ) {
        ($result.Findings | Where-Object { $_.CheckId -eq $Id -and $_.Resource -eq $Resource }).Detail | Should -Be $Detail
    }

    It 'HYG001 measures age from collection time' {
        ($result.Findings | Where-Object { $_.CheckId -eq 'HYG001' -and $_.Resource -eq 'web-stale' }).Detail | Should -Be 'Last run 151 days ago. Threshold: 90 days.'
        ($result.Findings | Where-Object { $_.CheckId -eq 'HYG001' -and $_.Resource -eq 'api-never-old' }).Detail | Should -Be 'Never run; created 182 days ago. Threshold: 90 days.'
    }

    It 'details explain the decision: <Id>' -ForEach @(
        @{ Id = 'SEC006'; Resource = 'api-never-old'; Detail = 'Fork pull request builds receive: full-access token.' }   # secrets enforced off at project level
        @{ Id = 'SEC012'; Resource = 'web-release'; Detail = "Not marked secret: DeployPassword (name suggests a credential); Endpoint (value matches a credential format) in stage 'Production'." }
        @{ Id = 'SEC009'; Resource = 'api-config'; Detail = 'Not marked secret: ApiToken (name suggests a credential); Endpoint (value matches a credential format).' }
        @{ Id = 'REL001'; Resource = 'web-ci'; Detail = '3 of the last 5 runs failed (60%); threshold 30%.' }                 # canceled ignored
        @{ Id = 'CST001'; Resource = 'carol@contoso.example'; Detail = 'Never signed in; license assigned 137 days ago. License: Basic + Test Plans; threshold 90 days.' }
        @{ Id = 'AGT003'; Resource = 'shared-linux/linux-02'; Detail = "Agent 'linux-02' in pool 'shared-linux' has been offline for 92 days; threshold 30." }
    ) {
        ($result.Findings | Where-Object { $_.CheckId -eq $Id -and $_.Resource -eq $Resource }).Detail | Should -Be $Detail
    }

    It 'AGT001 flags a self-hosted pool shared by different trust groups, never a hosted one' {
        $findings = InModuleScope adoscope -Parameters @{ Root = (Join-Path $PSScriptRoot '../..') } {
            param($Root)
            $context = Import-AdoScopeContext -Path (Join-Path $Root 'tests/Fixtures/Context/org.json')
            $check = Import-AdoScopeCheck -Path (Join-Path $Root 'src/Checks') | Where-Object Id -eq 'AGT001'
            $groups = @{ AGT001 = @{ trustGroups = @{ prod = @('web'); dev = @('api') } } }
            (Invoke-AdoScopeCheck -Check $check -Context $context -Parameters $groups).Findings
        }
        $findings.Resource | Should -Be 'shared-linux'
        $findings.Detail | Should -Be "Pool 'shared-linux' is used by trust groups dev, prod (projects: api, data, web)."
    }

    It 'every security, identity, pipeline and agent check maps to an OWASP CI/CD risk' {
        InModuleScope adoscope -Parameters @{ Root = (Join-Path $PSScriptRoot '../..') } {
            param($Root)
            foreach ($check in Import-AdoScopeCheck -Path (Join-Path $Root 'src/Checks') | Where-Object Category -in 'Security', 'Identity', 'Pipelines', 'Agents') {
                @($check.Standards).Count | Should -BeGreaterThan 0 -Because "$($check.Id) is a security check"
            }
        }
    }

    It 'every built-in check has complete metadata for reports' {
        InModuleScope adoscope -Parameters @{ Root = (Join-Path $PSScriptRoot '../..') } {
            param($Root)
            foreach ($check in Import-AdoScopeCheck -Path (Join-Path $Root 'src/Checks')) {
                $check.Rationale.Length | Should -BeGreaterThan 40 -Because "$($check.Id) needs a real rationale"
                $check.Remediation.Length | Should -BeGreaterThan 40 -Because "$($check.Id) needs actionable remediation"
            }
        }
    }
}

Describe 'Credential detection in variables (SEC009, SEC011)' {
    It '<Name> -> <Expected>' -ForEach @(
        @{ Name = 'ApiToken'; Looks = $false; Expected = 'ApiToken (name suggests a credential)' }
        @{ Name = 'DbPassword'; Looks = $false; Expected = 'DbPassword (name suggests a credential)' }
        @{ Name = 'TokenEndpoint'; Looks = $false; Expected = $null }          # points to a credential, does not hold it
        @{ Name = 'PasswordPolicyUrl'; Looks = $false; Expected = $null }
        @{ Name = 'ClientSecretId'; Looks = $false; Expected = $null }
        @{ Name = 'TokenUrl'; Looks = $true; Expected = 'TokenUrl (value matches a credential format)' }   # the value always wins
    ) {
        $check = InModuleScope adoscope -Parameters @{ Root = (Join-Path $PSScriptRoot '../..') } {
            param($Root) Import-AdoScopeCheck -Path (Join-Path $Root 'src/Checks') | Where-Object Id -eq 'SEC009'
        }
        $variables = @{ $Name = @{ isSecret = $false; _valueLooksLikeCredential = $Looks } }
        $found = InModuleScope adoscope -Parameters @{ V = $variables; P = $check.Parameters } {
            param($V, $P) Get-AdoScopeExposedVariable -Variable $V -NamePattern $P.namePatterns -NameExclusion $P.nameExclusions
        }
        $found | Should -Be $Expected
    }
}
