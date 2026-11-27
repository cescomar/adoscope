Describe 'docs/checks.md' {
    It 'is up to date with the check metadata (run ./tools/Update-CheckDoc.ps1)' {
        $root = Join-Path $PSScriptRoot '../..'
        $fresh = Join-Path $TestDrive 'checks.md'
        & (Join-Path $root 'tools/Update-CheckDoc.ps1') -Path $fresh
        # Compare content, not line endings: git on Windows checks files out with CRLF (core.autocrlf).
        $committed = (Get-Content -LiteralPath (Join-Path $root 'docs/checks.md') -Raw) -replace "`r`n", "`n"
        $committed | Should -BeExactly ((Get-Content -LiteralPath $fresh -Raw) -replace "`r`n", "`n")
    }
}
