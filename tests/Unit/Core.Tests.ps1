BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
}

Describe 'Get-AdoScopeFingerprint' {
    It 'is stable across case and distinguishes projects' {
        InModuleScope adoscope {
            $a = Get-AdoScopeFingerprint -CheckId 'SEC001' -Project 'Alpha' -ResourceId 'ABC'
            Get-AdoScopeFingerprint -CheckId 'sec001' -Project 'alpha' -ResourceId 'abc' | Should -Be $a
            Get-AdoScopeFingerprint -CheckId 'SEC001' -Project 'beta' -ResourceId 'abc' | Should -Not -Be $a
        }
    }
}

Describe 'Import-AdoScopeCheck' {
    BeforeAll {
        $script:valid = @'
@{ Id = 'XXX001'; Title = 't'; Category = 'c'; Severity = 'Low'; Rationale = 'r'; Remediation = 'm'
   Requires = @('Projects'); Test = { param($Context, $Parameters) } }
'@
    }

    It 'loads checks and defaults Parameters' {
        InModuleScope adoscope -Parameters @{ Root = $TestDrive; Body = $script:valid } {
            param($Root, $Body)
            $dir = New-Item -ItemType Directory (Join-Path $Root 'ok') -Force
            Set-Content (Join-Path $dir 'XXX001.ps1') $Body
            $check = Import-AdoScopeCheck -Path $dir
            $check.Id | Should -Be 'XXX001'
            $check.Parameters | Should -BeOfType [hashtable]
        }
    }

    It 'rejects <Case>' -ForEach @(
        @{ Case = 'invalid severity'; File = 'XXX001'; Replace = "'Low'"; With = "'Severe'"; Expected = '*invalid Severity*' }
        @{ Case = 'Id/file mismatch'; File = 'XXX002'; Replace = 'x'; With = 'x'; Expected = '*file name must match*' }
        @{ Case = 'missing Test'; File = 'XXX001'; Replace = 'Test = {'; With = 'NoTest = {'; Expected = "*'Test'*" }
        @{ Case = 'empty Requires'; File = 'XXX001'; Replace = "@('Projects')"; With = '@()'; Expected = "*'Requires'*" }
        @{ Case = 'an unknown standard id'; File = 'XXX001'; Replace = "Category = 'c'"; With = "Category = 'c'; Standards = @('CICD-SEC-11')"; Expected = '*invalid Standards*' }
    ) {
        InModuleScope adoscope -Parameters @{ Root = $TestDrive; Body = $script:valid.Replace($Replace, $With); File = $File; Expected = $Expected } {
            param($Root, $Body, $File, $Expected)
            $dir = New-Item -ItemType Directory (Join-Path $Root ([guid]::NewGuid())) -Force
            Set-Content (Join-Path $dir "$File.ps1") $Body
            { Import-AdoScopeCheck -Path $dir } | Should -Throw $Expected
        }
    }

    It 'rejects duplicate Ids across folders' {
        InModuleScope adoscope -Parameters @{ Root = $TestDrive; Body = $script:valid } {
            param($Root, $Body)
            foreach ($name in 'd1', 'd2') {
                $dir = New-Item -ItemType Directory (Join-Path $Root "dup/$name") -Force
                Set-Content (Join-Path $dir 'XXX001.ps1') $Body
            }
            { Import-AdoScopeCheck -Path (Join-Path $Root 'dup') } | Should -Throw '*Duplicate check Id*'
        }
    }

    It 'fails on a missing check folder instead of running zero checks' {
        InModuleScope adoscope -Parameters @{ Root = $TestDrive } {
            param($Root)
            $missing = Join-Path $Root 'nope'
            { Import-AdoScopeCheck -Path $missing } | Should -Throw
        }
    }
}

Describe 'Invoke-AdoScopeCheck' {
    BeforeAll {
        $script:fixtures = Join-Path $PSScriptRoot '../Fixtures'
    }

    It 'fills metadata, overrides parameters and tolerates missing optional fields' {
        InModuleScope adoscope -Parameters @{ F = $script:fixtures } {
            param($F)
            $context = Import-AdoScopeContext -Path "$F/Context/sample.json"
            $checks = Import-AdoScopeCheck -Path "$F/Checks" | Where-Object Id -eq 'TST001'

            $default = Invoke-AdoScopeCheck -Check $checks -Context $context
            $default.Findings.Resource | Should -Be 'beta'
            $default.Findings[0].Severity | Should -Be 'High'
            $default.Findings[0].Fingerprint | Should -Match '^[0-9a-f]{64}$'
            $default.Checks[0].Status | Should -Be 'Evaluated'

            $override = Invoke-AdoScopeCheck -Check $checks -Context $context -Parameters @{ TST001 = @{ visibility = 'private' } }
            $override.Findings.Resource | Should -Be 'alpha'
        }
    }

    It 'reports <Status> when required data is <Collection>' -ForEach @(
        @{ Collection = 'Forbidden'; Status = 'NotEvaluated' }
        @{ Collection = 'Failed'; Status = 'NotEvaluated' }
        @{ Collection = 'absent'; Status = 'NotEvaluated' }
        @{ Collection = 'Partial'; Status = 'Partial' }
    ) {
        InModuleScope adoscope -Parameters @{ F = $script:fixtures; Collection = $Collection; Status = $Status } {
            param($F, $Collection, $Status)
            $context = Import-AdoScopeContext -Path "$F/Context/sample.json"
            if ($Collection -eq 'absent') { $context.Collections.Remove('Projects') }
            else { $context.Collections.Projects.Status = $Collection }
            $checks = Import-AdoScopeCheck -Path "$F/Checks" | Where-Object Id -eq 'TST001'

            $result = Invoke-AdoScopeCheck -Check $checks -Context $context
            $result.Checks[0].Status | Should -Be $Status
            $result.Checks[0].Message | Should -Match 'Projects'
        }
    }

    It 'isolates a failing or misbehaving check and continues' {
        InModuleScope adoscope -Parameters @{ F = $script:fixtures } {
            param($F)
            $context = Import-AdoScopeContext -Path "$F/Context/sample.json"
            $base = @{ Title = 't'; Category = 'c'; Severity = 'Low'; Rationale = 'r'; Remediation = 'm'; Requires = @('Projects'); Parameters = @{} }
            $throws = $base.Clone(); $throws.Id = 'BAD001'; $throws.Test = { throw 'boom' }
            $leaks = $base.Clone(); $leaks.Id = 'BAD002'; $leaks.Test = { 'not a finding' }
            $good = Import-AdoScopeCheck -Path "$F/Checks" | Where-Object Id -eq 'TST001'

            $result = Invoke-AdoScopeCheck -Check $throws, $leaks, $good -Context $context -WarningAction SilentlyContinue
            ($result.Checks | Where-Object CheckId -eq 'BAD001').Status | Should -Be 'Error'
            ($result.Checks | Where-Object CheckId -eq 'BAD002').Status | Should -Be 'Error'
            ($result.Checks | Where-Object CheckId -eq 'TST001').Status | Should -Be 'Evaluated'
            @($result.Findings).Count | Should -Be 1
        }
    }
}

Describe 'Import-AdoScopeContext' {
    It 'rejects a collection with an unknown status' {
        $path = Join-Path $TestDrive 'bad.json'
        '{ "Organization": "o", "CollectedAt": "2026-01-01T00:00:00Z", "Collections": { "Projects": { "Status": "Maybe" } } }' | Set-Content $path
        InModuleScope adoscope -Parameters @{ P = $path } {
            param($P)
            $path = $P
            { Import-AdoScopeContext -Path $path } | Should -Throw '*valid Status*'
        }
    }
}
