function Import-AdoScopeConfig {
    <#
    .SYNOPSIS
        Loads adoscope.config.psd1 (PowerShell data file: safe to parse, comments allowed)
        and validates it against the loaded check catalog. Returns defaults without -Path.

    .DESCRIPTION
        @{
            Organization = 'fabrikam'
            Projects     = @('web', 'api')
            Checks       = @{
                Disabled   = @('HYG001')
                Parameters = @{ HYG001 = @{ days = 60 } }
                Severity   = @{ PIP003 = 'Medium' }
            }
            Suppressions = @(
                @{ Check = 'SEC001'; Project = 'web'; ResourceId = '<id>'; Reason = '...'; Expires = '2026-12-31' }
                @{ Check = 'SEC002'; Fingerprint = '<sha256>'; Reason = '...'; Expires = '2026-12-31' }
            )
        }
        Typos are errors: unknown keys, check IDs or parameter names would otherwise be ignored silently.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable[]]$Check
    )

    $raw = if ($Path) { Import-PowerShellDataFile -LiteralPath $Path } else { @{} }
    $where = "Config '$Path'"
    Assert-AdoScopeConfigKey -Table $raw -Allowed 'Organization', 'Projects', 'Checks', 'Suppressions' -Where $where
    $checks = if ($raw['Checks']) { $raw.Checks } else { @{} }
    Assert-AdoScopeConfigKey -Table $checks -Allowed 'Disabled', 'Parameters', 'Severity' -Where "$where Checks"

    $catalog = @{}
    foreach ($c in $Check) { $catalog[$c.Id] = $c }
    $config = @{
        Organization = $raw['Organization']
        Projects     = @($raw['Projects'] | Where-Object { $_ })
        Disabled     = @($checks['Disabled'] | Where-Object { $_ })
        Parameters   = if ($checks['Parameters']) { $checks.Parameters } else { @{} }
        Severity     = if ($checks['Severity']) { $checks.Severity } else { @{} }
        Suppressions = @()
    }

    foreach ($id in @($config.Disabled) + @($config.Parameters.Keys) + @($config.Severity.Keys)) {
        if (-not $catalog.ContainsKey($id)) { throw "$where references unknown check '$id'." }
    }
    foreach ($id in $config.Parameters.Keys) {
        if ($config.Parameters[$id] -isnot [hashtable]) { throw "$where Checks.Parameters.$id must be a hashtable." }
        Assert-AdoScopeConfigKey -Table $config.Parameters[$id] -Allowed @($catalog[$id].Parameters.Keys) -Where "$where Checks.Parameters.$id"
        Assert-AdoScopeParameterValue -Check $catalog[$id] -Override $config.Parameters[$id] -Where "$where Checks.Parameters.$id"
    }
    foreach ($id in $config.Severity.Keys) {
        if ($config.Severity[$id] -notin $script:Severities) { throw "$where has invalid severity '$($config.Severity[$id])' for $id." }
    }
    $config.Suppressions = @($raw['Suppressions'] | Where-Object { $_ } | ForEach-Object {
            ConvertTo-AdoScopeSuppression -Entry $_ -Catalog $catalog -Where $where
        })
    $config
}

function ConvertTo-AdoScopeSuppression {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][hashtable]$Catalog,
        [Parameter(Mandatory)][string]$Where
    )

    if ($Entry -isnot [hashtable]) { throw "$Where Suppressions entries must be hashtables." }
    Assert-AdoScopeConfigKey -Table $Entry -Allowed 'Check', 'Fingerprint', 'Project', 'ResourceId', 'Reason', 'Expires' -Where "$Where Suppressions"
    $label = "$Where suppression for '$($Entry['Check'])'"
    if (-not $Catalog.ContainsKey([string]$Entry['Check'])) { throw "$label references an unknown check." }
    if ([string]::IsNullOrWhiteSpace($Entry['Reason'])) { throw "$label needs a Reason." }
    if (-not ($Entry['Fingerprint'] -or $Entry['ResourceId'])) { throw "$label needs a Fingerprint or a ResourceId." }
    $expires = [datetime]::MinValue
    $ok = [datetime]::TryParseExact([string]$Entry['Expires'], 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, 'None', [ref]$expires)
    if (-not $ok) { throw "$label needs Expires as 'yyyy-MM-dd'." }

    @{
        Check = $Entry.Check; Fingerprint = $Entry['Fingerprint']; Project = $Entry['Project']
        ResourceId = $Entry['ResourceId']; Reason = $Entry.Reason; Expires = $expires
    }
}

function Assert-AdoScopeConfigKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Table,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Allowed,
        [Parameter(Mandatory)][string]$Where
    )

    if ($Table -isnot [hashtable]) { throw "$Where must be a hashtable." }
    $unknown = @($Table.Keys | Where-Object { $_ -notin $Allowed })
    if ($unknown) { throw "$Where has unknown key(s): $($unknown -join ', '). Allowed: $($Allowed -join ', ')." }
}

function Assert-AdoScopeParameterValue {
    <#
    .SYNOPSIS
        Rejects override values that do not fit the check: the type follows the default
        (integer, number, boolean, string, list of strings, table of string lists), numbers
        must be positive, then the check's own Validate scriptblock checks meaning and coherence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Check,
        [Parameter(Mandatory)][hashtable]$Override,
        [Parameter(Mandatory)][string]$Where
    )

    $isText = { param($v) @($v | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -eq 0 }
    foreach ($name in $Override.Keys) {
        $value = $Override[$name]
        $default = $Check.Parameters[$name]
        $expected = switch ($true) {
            ($default -is [bool]) { if ($value -isnot [bool]) { '$true or $false' } }
            ($default -is [int] -or $default -is [long]) { if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1) { 'a whole number >= 1' } }
            ($default -is [double]) { if (($value -isnot [int] -and $value -isnot [double]) -or $value -le 0) { 'a number > 0' } }
            ($default -is [string]) { if ($value -isnot [string] -or -not $value.Trim()) { 'a non-empty string' } }
            ($default -is [array]) { if (-not (& $isText $value)) { "a list of non-empty strings, e.g. @('a', 'b')" } }
            ($default -is [hashtable]) { if ($value -isnot [hashtable] -or @($value.Values | Where-Object { -not (& $isText $_) })) { "a table of string lists, e.g. @{ name = @('a', 'b') }" } }
        }
        if ($expected) { throw "$Where.$name has invalid value '$(@($value) -join ', ')': expected $expected." }
    }
    if (-not $Check['Validate']) { return }
    $effective = $Check.Parameters.Clone()
    foreach ($name in $Override.Keys) { $effective[$name] = $Override[$name] }
    $problems = @(& $Check.Validate $effective)
    if ($problems) { throw "$Where is invalid: $($problems -join '; ')." }
}
