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
        $report.SchemaVersion | Should -Be 1
        $report.Scope.Mode | Should -Be 'Offline'
        # The data's date, not the report's: an old context must not look like a fresh audit.
        ([datetime]$report.Scope.CollectedAt).ToUniversalTime() | Should -Be ([datetime]((Get-Content $runArgs.ContextPath -Raw | ConvertFrom-Json -AsHashtable).CollectedAt)).ToUniversalTime()
        $report.Scope.Projects | Should -Not -BeNullOrEmpty
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

Describe 'adoscope.ps1 (CI wrapper)' {
    It 'accepts every Invoke-AdoScope parameter, with the same parameter sets' {
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $cmdlet = (Get-Command Invoke-AdoScope).Parameters
        $wrapper = (Get-Command (Join-Path $PSScriptRoot '../../adoscope.ps1')).Parameters
        foreach ($name in $cmdlet.Keys | Where-Object { $_ -notin $common }) {
            $wrapper.Keys | Should -Contain $name -Because "a parameter added to Invoke-AdoScope must also be forwarded by adoscope.ps1"
            @($wrapper[$name].ParameterSets.Keys | Sort-Object) | Should -Be @($cmdlet[$name].ParameterSets.Keys | Sort-Object) -Because "parameter set of $name"
        }
    }
}
