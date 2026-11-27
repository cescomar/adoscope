BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
    $script:fixtures = Join-Path $PSScriptRoot '../Fixtures'
}

Describe 'Invoke-AdoScope with a config file' {
    BeforeAll {
        $script:report = Invoke-AdoScope -ContextPath "$fixtures/Context/org.json" -ConfigPath "$fixtures/Config/org.config.psd1" `
            -Quiet -PassThru
        function script:Get-Finding($Check, $Resource) { $report.Findings | Where-Object { $_.CheckId -eq $Check -and $_.Resource -eq $Resource } }
    }

    It 'skips disabled checks and lists them as Disabled' {
        ($report.Checks | Where-Object CheckId -eq 'SEC007').Status | Should -Be 'Disabled'
        $report.Findings.CheckId | Should -Not -Contain 'SEC007'
    }

    It 'applies parameter and severity overrides' {
        @($report.Findings | Where-Object CheckId -eq 'HYG001').Resource | Should -Be 'api-never-old'
        (Get-Finding 'PIP003' 'web-classic').Severity | Should -Be 'Medium'
    }

    It 'suppresses only what an active suppression matches' {
        (Get-Finding 'SEC001' 'api-generic').Suppressed | Should -BeTrue
        (Get-Finding 'SEC001' 'api-generic').SuppressionReason | Should -Be 'Accepted risk: read-only mirror credential.'
        (Get-Finding 'SEC001' 'web-azure-secret').Suppressed | Should -BeFalse
        (Get-Finding 'SEC002' 'web-azure-legacy').Suppressed | Should -BeFalse   # expired
    }

    It 'reports each suppression as Active, Expired or Unmatched' {
        ($report.Suppressions | ForEach-Object { "$($_.Check)=$($_.Status)" }) | Should -Be 'SEC001=Active', 'SEC002=Expired', 'PIP003=Unmatched'
    }

    It 'shows suppressed count and stale suppressions on the console' {
        $text = Invoke-AdoScope -ContextPath "$fixtures/Context/org.json" -ConfigPath "$fixtures/Config/org.config.psd1" 6>&1 | Out-String
        $text | Should -Not -Match '\[SEC001\].*api/api-generic'
        $text | Should -Match 'Configuration \(2\)'
        $text | Should -Match 'suppressed: 1 \| checks: \d+/\d+ fully evaluated'
    }
}

Describe 'Import-AdoScopeConfig validation' {
    It 'rejects <Case>' -ForEach @(
        @{ Case = 'an unknown top-level key'; Body = "@{ Organisation = 'x' }"; Expected = '*unknown key(s): Organisation*' }
        @{ Case = 'an unknown check in Disabled'; Body = "@{ Checks = @{ Disabled = @('SEC999') } }"; Expected = "*unknown check 'SEC999'*" }
        @{ Case = 'a misspelled parameter'; Body = '@{ Checks = @{ Parameters = @{ HYG001 = @{ day = 30 } } } }'; Expected = '*unknown key(s): day*' }
        @{ Case = 'an invalid severity'; Body = "@{ Checks = @{ Severity = @{ PIP003 = 'Urgent' } } }"; Expected = "*invalid severity 'Urgent'*" }
        @{ Case = 'a suppression without Reason'; Body = "@{ Suppressions = @(@{ Check = 'SEC001'; ResourceId = 'x'; Expires = '2099-01-01' }) }"; Expected = '*needs a Reason*' }
        @{ Case = 'a suppression without target'; Body = "@{ Suppressions = @(@{ Check = 'SEC001'; Reason = 'r'; Expires = '2099-01-01' }) }"; Expected = '*Fingerprint or a ResourceId*' }
        @{ Case = 'a non-ISO expiry'; Body = "@{ Suppressions = @(@{ Check = 'SEC001'; ResourceId = 'x'; Reason = 'r'; Expires = '31/12/2099' }) }"; Expected = "*yyyy-MM-dd*" }
    ) {
        $path = Join-Path $TestDrive 'bad.config.psd1'
        Set-Content -LiteralPath $path -Value $Body
        { Invoke-AdoScope -ContextPath "$fixtures/Context/org.json" -ConfigPath $path 6>$null } | Should -Throw $Expected
    }
}

Describe 'Resolve-AdoScopeSuppression' {
    BeforeAll {
        $script:newFinding = {
            InModuleScope adoscope {
                $f = New-AdoScopeFinding -Project 'web' -Resource 'r' -ResourceId 'id-1' -Detail 'd'
                $f.CheckId = 'SEC001'
                $f.Fingerprint = Get-AdoScopeFingerprint -CheckId 'SEC001' -Project 'web' -ResourceId 'id-1'
                $f
            }
        }
    }

    It 'matches by fingerprint and stays active through the expiry day' {
        $finding = & $newFinding
        $status = InModuleScope adoscope -Parameters @{ F = $finding } {
            param($F)
            $s = @{ Check = 'SEC001'; Fingerprint = $F.Fingerprint; Reason = 'ok'; Expires = [datetime]'2026-06-30' }
            Resolve-AdoScopeSuppression -Finding $F -Suppression $s -Today ([datetime]'2026-06-30')
        }
        $status.Status | Should -Be 'Active'
        $finding.Suppressed | Should -BeTrue
    }

    It 'expires the day after Expires' {
        $finding = & $newFinding
        $status = InModuleScope adoscope -Parameters @{ F = $finding } {
            param($F)
            $s = @{ Check = 'SEC001'; Fingerprint = $F.Fingerprint; Reason = 'ok'; Expires = [datetime]'2026-06-30' }
            Resolve-AdoScopeSuppression -Finding $F -Suppression $s -Today ([datetime]'2026-07-01')
        }
        $status.Status | Should -Be 'Expired'
        $finding.Suppressed | Should -BeFalse
    }

    It 'does not match a ResourceId in another project' {
        $finding = & $newFinding
        $status = InModuleScope adoscope -Parameters @{ F = $finding } {
            param($F)
            $s = @{ Check = 'SEC001'; Project = 'api'; ResourceId = 'id-1'; Reason = 'ok'; Expires = [datetime]'2099-01-01' }
            Resolve-AdoScopeSuppression -Finding $F -Suppression $s
        }
        $status.Status | Should -Be 'Unmatched'
    }
}
