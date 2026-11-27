BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
    $script:fixtures = Join-Path $PSScriptRoot '../Fixtures'
    $script:runArgs = @{
        ContextPath = Join-Path $script:fixtures 'Context/sample.json'
        CheckPath   = Join-Path $script:fixtures 'Checks'
    }
}

Describe 'Invoke-AdoScope' {
    It 'writes a JSON report with metadata, rules, coverage and findings' {
        $out = Join-Path $TestDrive 'report.json'
        Invoke-AdoScope @runArgs -JsonPath $out -Quiet
        $report = Get-Content $out -Raw | ConvertFrom-Json

        $report.Tool | Should -Be 'adoscope'
        $report.Organization | Should -Be 'fabrikam-sample'
        $report.Rules.Id | Should -Be 'TST001', 'TST002'
        $report.Findings.CheckId | Should -Be 'TST001'
        ($report.Checks | Where-Object CheckId -eq 'TST002').Status | Should -Be 'NotEvaluated'
    }

    It 'prints findings, coverage gaps and summary to the console' {
        $text = (Invoke-AdoScope @runArgs 6>&1 | Out-String)

        $text | Should -Match '\[TST001\].*beta/beta'
        $text | Should -Match 'Coverage gaps \(1\)'
        $text | Should -Match 'High: 1'
        $text | Should -Match 'checks: 1/2 fully evaluated'
    }
}
