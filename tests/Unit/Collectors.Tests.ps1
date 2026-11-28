BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
}

Describe 'Get-AdoVariableGroup' {
    It 'never keeps variable values, only whether they look like credentials' {
        # Synthetic credential-shaped value (legacy PAT format), not a real token.
        $script:fakePat = 'abcd2345' * 6 + 'abcd'
        Mock Invoke-AdoScopeListRequest -ModuleName adoscope {
            @{ id = 7; name = 'g'; type = 'Vsts'; variables = @{
                    Plain  = @{ value = 'eu-west' }
                    Leaked = @{ value = "token=$script:fakePat" }
                    Locked = @{ value = $null; isSecret = $true }
                } }
        }
        Mock Get-AdoPipelinePermission -ModuleName adoscope { @{ pipelines = @() } }

        $group = InModuleScope adoscope {
            Get-AdoVariableGroup -Organization 'o' -Auth ([pscustomobject]@{}) -Project @{ id = 'p'; name = 'p' }
        }
        ($group | ConvertTo-Json -Depth 10) | Should -Not -Match "eu-west|$script:fakePat"
        $group.variables.Leaked._valueLooksLikeCredential | Should -BeTrue
        $group.variables.Plain._valueLooksLikeCredential | Should -BeFalse
        $group.variables.Locked.isSecret | Should -BeTrue
    }
}

Describe 'Get-AdoBuildDefinition' {
    It 'keeps only what checks use: no variable values, no classic task inputs' {
        # Synthetic credential-shaped value (legacy PAT format), not a real token.
        $script:fakePat = 'wxyz2345' * 6 + 'wxyz'
        Mock Invoke-AdoScopeListRequest -ModuleName adoscope {
            @{
                id = 9; name = 'classic'; createdDate = '2026-01-01T00:00:00Z'
                process   = @{ type = 1; phases = @(@{ steps = @(@{ inputs = @{ script = "curl -u ci:$script:fakePat https://example.invalid" } }) }) }
                variables = @{ DeployToken = @{ value = $script:fakePat }; Region = @{ value = 'eu-west' }; Locked = @{ isSecret = $true } }
                triggers  = @(@{ triggerType = 'pullRequest'; branchFilters = @('+main'); forks = @{ enabled = $true; allowSecrets = $true } })
            }
        }
        $definition = InModuleScope adoscope { Get-AdoBuildDefinition -Organization 'o' -Auth ([pscustomobject]@{}) -Project @{ id = 'p'; name = 'web' } }
        ($definition | ConvertTo-Json -Depth 20) | Should -Not -Match "$script:fakePat|eu-west|curl"
        $definition.process.type | Should -Be 1
        $definition.triggers[0].forks.allowSecrets | Should -BeTrue
        $definition.variables.DeployToken._valueLooksLikeCredential | Should -BeTrue
        $definition.variables.Locked.isSecret | Should -BeTrue
    }
}

Describe 'Get-AdoReleaseDefinition' {
    It 'keeps stage approvals without variable values, and isolates an unreadable definition' {
        # Synthetic credential-shaped value (legacy PAT format), not a real token.
        $script:fakePat = 'rstu2345' * 6 + 'rstu'
        Mock Invoke-AdoScopeListRequest -ModuleName adoscope { @{ id = 1; name = 'ok' }; @{ id = 2; name = 'denied' } }
        Mock Invoke-AdoScopeRequest -ModuleName adoscope {
            if ($Uri.AbsolutePath -like '*/definitions/2') { throw [System.Net.Http.HttpRequestException]::new('HTTP 403', $null, [System.Net.HttpStatusCode]::Forbidden) }
            [pscustomobject]@{ Content = @{
                    variables    = @{ DeployToken = @{ value = $script:fakePat } }
                    environments = @(@{ id = 7; name = 'Prod'; variables = @{ Region = @{ value = 'eu-west' } }
                            preDeployApprovals = @{ approvals = @(@{ isAutomated = $false; approver = @{ uniqueName = 'someone@contoso.example' } })
                                approvalOptions = @{ releaseCreatorCanBeApprover = $true } }
                            preDeploymentGates = @{ gates = @() } })
                } }
        }
        $items = InModuleScope adoscope { @(Get-AdoReleaseDefinition -Organization 'o' -Auth ([pscustomobject]@{}) -Project @{ id = 'p'; name = 'web' }) }
        ($items | ConvertTo-Json -Depth 20) | Should -Not -Match "$script:fakePat|eu-west|someone@"
        $ok = $items | Where-Object name -eq 'ok'
        $ok.variables.DeployToken._valueLooksLikeCredential | Should -BeTrue
        $ok.environments[0].approvals[0].isAutomated | Should -BeFalse
        $ok.environments[0].releaseCreatorCanBeApprover | Should -BeTrue
        ($items | Where-Object name -eq 'denied')._error | Should -Match "release definition of 'denied': HTTP 403"
    }
}

Describe 'Get-AdoScopeContext organization-wide collections' {
    It 'marks an organization collection Forbidden when the call is denied, without failing the run' {
        Mock Get-AdoProject -ModuleName adoscope { @(@{ id = 'p1'; name = 'alpha' }) }
        Mock Get-AdoUserEntitlement -ModuleName adoscope {
            throw [System.Net.Http.HttpRequestException]::new('HTTP 403', $null, [System.Net.HttpStatusCode]::Forbidden)
        }
        $context = InModuleScope adoscope {
            Get-AdoScopeContext -Organization 'o' -Auth ([pscustomobject]@{}) -Collection 'UserEntitlements' -WarningAction SilentlyContinue
        }
        $context.Collections.UserEntitlements.Status | Should -Be 'Forbidden'
        $context.Collections.UserEntitlements.Error | Should -Match '\(organization\): HTTP 403'
    }
}

Describe 'Get-AdoAdminGroup' {
    It 'expands nested groups once, survives cycles, and drops built-in service identities' {
        Mock Invoke-AdoScopeListRequest -ModuleName adoscope {
            switch -Wildcard ($Uri.AbsolutePath) {
                '*/graph/groups' {
                    @{ descriptor = 'vssgp.pca'; principalName = '[o]\Project Collection Administrators'; domain = 'vstfs:///Framework/IdentityDomain/x' }
                    @{ descriptor = 'vssgp.nested'; principalName = '[o]\Ops'; domain = 'vstfs:///Framework/IdentityDomain/x' }
                }
                '*/graph/users' {
                    @{ descriptor = 'aad.a'; principalName = 'a@contoso.example'; origin = 'aad'; subjectKind = 'user' }
                    @{ descriptor = 'aad.b'; principalName = 'b@contoso.example'; origin = 'aad'; subjectKind = 'user' }
                    @{ descriptor = 'svc.build'; principalName = 'Build Service'; origin = 'vsts'; subjectKind = 'user' }
                }
                '*/Memberships/vssgp.pca' { @{ memberDescriptor = 'aad.a' }; @{ memberDescriptor = 'vssgp.nested' }; @{ memberDescriptor = 'svc.build' } }
                # Cycle back to the parent, plus a duplicate of a direct member.
                '*/Memberships/vssgp.nested' { @{ memberDescriptor = 'vssgp.pca' }; @{ memberDescriptor = 'aad.b' }; @{ memberDescriptor = 'aad.a' } }
            }
        }
        $group = InModuleScope adoscope { Get-AdoAdminGroup -Organization 'o' -Auth ([pscustomobject]@{}) }
        $group.scope | Should -Be 'organization'
        @($group.members.principalName | Sort-Object) | Should -Be 'a@contoso.example', 'b@contoso.example'
        ($group.members | Where-Object descriptor -eq 'aad.b').via | Should -Be '[o]\Ops'
        Should -Invoke Invoke-AdoScopeListRequest -ModuleName adoscope -Times 2 -Exactly -ParameterFilter { $Uri.AbsolutePath -like '*/Memberships/*' }
    }
}

Describe 'Per-resource failures' {
    It 'keeps every service connection when the permissions of one cannot be read' {
        Mock Get-AdoProject -ModuleName adoscope { @(@{ id = 'p1'; name = 'alpha' }) }
        Mock Invoke-AdoScopeListRequest -ModuleName adoscope { @(@{ id = 'e1'; name = 'readable' }, @{ id = 'e2'; name = 'denied' }) }
        Mock Get-AdoPipelinePermission -ModuleName adoscope {
            if ($ResourceId -eq 'e2') { throw [System.Net.Http.HttpRequestException]::new('HTTP 403', $null, [System.Net.HttpStatusCode]::Forbidden) }
            @{ allPipelines = @{ authorized = $true } }
        }
        $collection = InModuleScope adoscope {
            (Get-AdoScopeContext -Organization 'o' -Auth ([pscustomobject]@{}) -Collection 'ServiceConnections' -WarningAction SilentlyContinue).Collections.ServiceConnections
        }
        $collection.Status | Should -Be 'Partial'
        $collection.Items.name | Should -Be 'readable', 'denied'
        ($collection.Items | Where-Object name -eq 'readable')._pipelinePermissions.allPipelines.authorized | Should -BeTrue
        ($collection.Items | Where-Object name -eq 'denied')._error | Should -Match "pipeline permissions of 'denied': HTTP 403"
        $collection.Error | Should -Match 'alpha: pipeline permissions'
    }
}
