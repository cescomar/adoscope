Describe 'docs/checks.md' {
    It 'is up to date with the check metadata (run ./tools/Update-CheckDoc.ps1)' {
        $root = Join-Path $PSScriptRoot '../..'
        $fresh = Join-Path $TestDrive 'checks.md'
        & (Join-Path $root 'tools/Update-CheckDoc.ps1') -Path $fresh
        Get-Content -LiteralPath (Join-Path $root 'docs/checks.md') -Raw | Should -BeExactly (Get-Content -LiteralPath $fresh -Raw)
    }
}
