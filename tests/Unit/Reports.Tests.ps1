BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
    $script:fixtures = Join-Path $PSScriptRoot '../Fixtures'
    $script:runArgs = @{ ContextPath = Join-Path $script:fixtures 'Context/sample.json'; CheckPath = Join-Path $script:fixtures 'Checks'; Quiet = $true; PassThru = $true }
}

Describe 'Report writers' {
    BeforeAll { $script:report = Invoke-AdoScope @runArgs }

    It 'creates SARIF 2.1.0 with rules and findings' {
        $sarif = InModuleScope adoscope -Parameters @{ Report = $report } { param($Report) ConvertTo-AdoScopeSarifReport -Report $Report | ConvertFrom-Json -Depth 20 }
        $sarif.'$schema' | Should -Be 'https://json.schemastore.org/sarif-2.1.0.json'
        $sarif.version | Should -Be '2.1.0'
        $sarif.runs.Count | Should -Be 1
        $sarif.runs[0].tool.driver.rules.Count | Should -Be 2
        $sarif.runs[0].results[0].level | Should -Be 'error'
        $sarif.runs[0].results[0].partialFingerprints.'adoscope/v1' | Should -Be $report.Findings[0].Fingerprint
    }

    It 'represents suppressions and incomplete checks in SARIF' {
        $report.Findings[0].Suppressed = $true
        $report.Findings[0].SuppressionReason = 'Accepted test risk.'
        $sarif = InModuleScope adoscope -Parameters @{ Report = $report } { param($Report) ConvertTo-AdoScopeSarifReport -Report $Report | ConvertFrom-Json -Depth 20 }
        $sarif.runs[0].results[0].suppressions[0].status | Should -Be 'accepted'
        $sarif.runs[0].invocations[0].toolExecutionNotifications[0].descriptor.id | Should -Be 'TST002'
    }

    It 'HTML-encodes finding values and has no external references' {
        $report.Findings[0].Resource = '<script>alert(1)</script>'
        $html = InModuleScope adoscope -Parameters @{ Report = $report } { param($Report) ConvertTo-AdoScopeHtmlReport -Report $Report }
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Not -Match 'https?://'
    }
}

Describe 'adoscope CI wrapper exit codes' {
    BeforeAll {
        $script:pwsh = Join-Path $PSHOME 'pwsh'
        if ($IsWindows) { $script:pwsh += '.exe' }
        $script:wrapper = Join-Path $PSScriptRoot '../../adoscope.ps1'
        $script:context = Join-Path $script:fixtures 'Context/sample.json'
        $script:checks = Join-Path $script:fixtures 'Checks'
    }

    It 'returns <Code>' -ForEach @(
        @{ Code = 0; Arguments = @('-FailOn', 'None', '-AllowIncompleteCoverage') }
        @{ Code = 1; Arguments = @('-FailOn', 'High', '-AllowIncompleteCoverage') }
        @{ Code = 2; Arguments = @('-FailOn', 'None') }
        @{ Code = 3; Arguments = @('-ContextPath', 'missing.json') }
    ) {
        param($Code, $Arguments)
        $arguments = @('-NoProfile', '-File', $wrapper, '-ContextPath', $context, '-CheckPath', $checks, '-Quiet') + $Arguments
        if ($Code -eq 3) { $arguments = @('-NoProfile', '-File', $wrapper, '-ContextPath', 'missing.json', '-Quiet') }
        & $pwsh @arguments 2>$null
        $LASTEXITCODE | Should -Be $Code
    }
}
