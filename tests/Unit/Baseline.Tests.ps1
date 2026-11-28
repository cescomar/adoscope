BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
    $script:root = Join-Path $PSScriptRoot '../..'
    $script:contextPath = Join-Path $root 'tests/Fixtures/Context/org.json'
    $script:pwsh = (Get-Process -Id $PID).Path

    # Baseline = today's report minus the SEC009 finding, plus one finding that no longer exists
    # (an SEC001 resource, no project) and one of a project outside today's scope.
    $script:fullPath = Join-Path $TestDrive 'full.json'
    Invoke-AdoScope -ContextPath $contextPath -JsonPath $fullPath -Quiet
    $baseline = Get-Content $fullPath -Raw | ConvertFrom-Json -AsHashtable
    $baseline.Findings = @($baseline.Findings | Where-Object { $_.CheckId -ne 'SEC009' }) +
    @(@{ CheckId = 'SEC001'; Fingerprint = 'f' * 64 }, @{ CheckId = 'SEC001'; Project = 'archived'; Fingerprint = 'e' * 64 })
    $script:baselinePath = Join-Path $TestDrive 'baseline.json'
    $baseline | ConvertTo-Json -Depth 20 | Set-Content $baselinePath
}

Describe 'Invoke-AdoScope -BaselinePath' {
    It 'marks known findings, counts new and resolved ones' {
        $report = Invoke-AdoScope -ContextPath $contextPath -BaselinePath $baselinePath -Quiet -PassThru
        @($report.Findings | Where-Object { -not $_.InBaseline }).CheckId | Should -Be 'SEC009'
        $report.Baseline.New | Should -Be 1
        $report.Baseline.Resolved | Should -Be 1
        $report.Baseline.Unverified | Should -Be 1   # project 'archived' is not in scope: not proof of a fix
        $report.Baseline.Existing | Should -Be (@($report.Findings).Count - 1)
    }

    It 'writes SARIF baselineState' {
        $sarifPath = Join-Path $TestDrive 'b.sarif'
        Invoke-AdoScope -ContextPath $contextPath -BaselinePath $baselinePath -SarifPath $sarifPath -Quiet
        $results = (Get-Content $sarifPath -Raw | ConvertFrom-Json).runs[0].results
        @($results | Where-Object baselineState -eq 'new').ruleId | Should -Be 'SEC009'
        @($results | Where-Object baselineState -eq 'unchanged').Count | Should -Be ($results.Count - 1)
    }

    It 'rejects a baseline from another organization' {
        $other = Join-Path $TestDrive 'other.json'
        (Get-Content $baselinePath -Raw) -replace '"contoso-sample"', '"someone-else"' | Set-Content $other
        { Invoke-AdoScope -ContextPath $contextPath -BaselinePath $other -Quiet } | Should -Throw "*belongs to organization 'someone-else'*"
    }

    It 'rejects a file that is not an adoscope report' {
        $bad = Join-Path $TestDrive 'bad.json'
        '{ "Findings": [] }' | Set-Content $bad
        { Invoke-AdoScope -ContextPath $contextPath -BaselinePath $bad -Quiet } | Should -Throw '*not an adoscope JSON report*'
    }

    It 'does not count findings as resolved when <Case>' -ForEach @(
        @{ Case = 'their collection became unreadable (403)'; Config = $null; Forbid = 'ServiceConnections' }
        @{ Case = 'the check was disabled'; Config = "@{ Checks = @{ Disabled = @('SEC001', 'SEC002') } }"; Forbid = $null }
        @{ Case = 'a threshold changed'; Config = '@{ Checks = @{ Parameters = @{ HYG001 = @{ days = 365 } } } }'; Forbid = $null }
    ) {
        $context = Get-Content $contextPath -Raw | ConvertFrom-Json -AsHashtable
        if ($Forbid) { $context.Collections[$Forbid] = @{ Status = 'Forbidden'; Items = @(); Error = 'HTTP 403' } }
        $changedContext = Join-Path $TestDrive 'changed.json'
        $context | ConvertTo-Json -Depth 50 | Set-Content $changedContext
        $arguments = @{ ContextPath = $changedContext; BaselinePath = $fullPath; Quiet = $true; PassThru = $true; WarningAction = 'SilentlyContinue' }
        if ($Config) { $arguments.ConfigPath = Join-Path $TestDrive 'c.psd1'; Set-Content $arguments.ConfigPath $Config }
        $report = Invoke-AdoScope @arguments
        $report.Baseline.Resolved | Should -Be 0
        $report.Baseline.Unverified | Should -BeGreaterThan 0
    }
}

Describe 'adoscope.ps1 -FailOn with a baseline' {
    It 'exits <Exit> when <Case>' -ForEach @(
        @{ Case = 'the only new finding is Critical and FailOn is High'; Baseline = 'baseline'; FailOn = 'High'; Exit = 1 }
        @{ Case = 'nothing is new'; Baseline = 'full'; FailOn = 'Low'; Exit = 0 }
    ) {
        $path = if ($Baseline -eq 'full') { $fullPath } else { $baselinePath }
        # AGT001 is NotEvaluated in this fixture (no trust groups): coverage is not what this test is about.
        & $pwsh -NoProfile -File (Join-Path $root 'adoscope.ps1') -ContextPath $contextPath -BaselinePath $path -FailOn $FailOn -AllowIncompleteCoverage -Quiet
        $LASTEXITCODE | Should -Be $Exit
    }
}
