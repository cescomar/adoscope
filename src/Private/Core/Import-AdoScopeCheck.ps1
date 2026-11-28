function Import-AdoScopeCheck {
    <#
    .SYNOPSIS
        Loads and validates every check file (<ID>.ps1) under the given folders.
        Invalid or duplicate checks are terminating errors: a broken catalog must
        never silently produce a shorter report.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string[]]$Path
    )

    # Get-ChildItem -Recurse treats a missing path as a name filter and returns nothing.
    foreach ($folder in $Path) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw "Check folder '$folder' not found." }
    }
    $seen = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Path -Filter '*.ps1' -Recurse -File) {
        $check = & $file.FullName
        Assert-AdoScopeCheck -Check $check -File $file
        if ($seen.ContainsKey($check.Id)) {
            throw "Duplicate check Id '$($check.Id)' in '$($file.FullName)' and '$($seen[$check.Id])'."
        }
        $seen[$check.Id] = $file.FullName
        if (-not $check.ContainsKey('Parameters')) { $check.Parameters = @{} }
        $check.Standards = @($check['Standards'])
        $check
    }
}

function Assert-AdoScopeCheck {
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Check,
        [Parameter(Mandatory)][System.IO.FileInfo]$File
    )

    $where = "Check file '$($File.FullName)'"
    if ($Check -isnot [hashtable]) { throw "$where must return a single hashtable." }

    foreach ($key in 'Id', 'Title', 'Category', 'Severity', 'Rationale', 'Remediation') {
        if ($Check[$key] -isnot [string] -or [string]::IsNullOrWhiteSpace($Check[$key])) {
            throw "$where is missing required string '$key'."
        }
    }
    if ($Check.Id -cnotmatch '^[A-Z]{3}\d{3}$') { throw "$where has invalid Id '$($Check.Id)' (expected e.g. SEC001)." }
    if ($Check.Id -ne $File.BaseName) { throw "$where declares Id '$($Check.Id)'; file name must match." }
    if ($Check.Severity -notin $script:Severities) { throw "$where has invalid Severity '$($Check.Severity)'." }
    if ($Check.Test -isnot [scriptblock]) { throw "$where is missing scriptblock 'Test'." }
    if (@($Check.Requires).Count -eq 0 -or @($Check.Requires | Where-Object { $_ -isnot [string] })) {
        throw "$where must declare 'Requires' as one or more collection names."
    }
    if ($Check.ContainsKey('Parameters') -and $Check.Parameters -isnot [hashtable]) {
        throw "$where has 'Parameters' that is not a hashtable."
    }
    $unknownRequired = @($Check['RequiredParameters'] | Where-Object { $_ -isnot [string] -or -not ($Check['Parameters'] -is [hashtable] -and $Check.Parameters.ContainsKey($_)) })
    if ($unknownRequired) { throw "$where lists RequiredParameters '$($unknownRequired -join ', ')' that are not in 'Parameters'." }
    if ($Check.ContainsKey('Validate') -and $Check.Validate -isnot [scriptblock]) { throw "$where has 'Validate' that is not a scriptblock." }
    # OWASP Top 10 CI/CD Security Risks ids only (https://owasp.org/www-project-top-10-ci-cd-security-risks/).
    $badStandard = @($Check['Standards'] | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^CICD-SEC-(10|[1-9])$' })
    if ($badStandard) { throw "$where has invalid Standards '$($badStandard -join ', ')' (expected CICD-SEC-1 .. CICD-SEC-10)." }
}
