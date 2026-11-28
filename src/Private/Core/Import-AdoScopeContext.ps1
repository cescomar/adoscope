function Import-AdoScopeContext {
    <#
    .SYNOPSIS
        Loads a context previously saved as JSON and validates its shape.

    .DESCRIPTION
        Context shape (hashtables, so checks can probe optional keys under StrictMode):
          @{
            SchemaVersion = 1                       # absent in contexts saved before 0.3.0 = 1
            Organization = 'org'
            CollectedAt  = '2026-01-01T00:00:00Z'
            Collections  = @{
              Projects = @{ Status = 'Ok'; Items = @( @{...}, ... ); Error = $null }
            }
          }
        Status: Ok | Partial | Failed | Forbidden. An absent collection was not collected.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $context = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $where = "Context file '$Path'"
    if ($context -isnot [hashtable]) { throw "$where must contain a JSON object." }
    if ([string]::IsNullOrWhiteSpace($context['Organization'])) { throw "$where is missing 'Organization'." }
    if ($context['Collections'] -isnot [hashtable]) { throw "$where is missing 'Collections' object." }
    if ($null -eq ($context['CollectedAt'] -as [datetime])) { throw "$where is missing a valid 'CollectedAt' timestamp." }
    $schema = if ($context.ContainsKey('SchemaVersion')) { $context.SchemaVersion -as [int] } else { 1 }
    if ($schema -notin 1..$script:ContextSchemaVersion) {
        throw "$where has SchemaVersion '$($context.SchemaVersion)'; this adoscope reads 1 to $($script:ContextSchemaVersion). Update adoscope or collect again."
    }

    foreach ($name in @($context.Collections.Keys)) {
        $collection = $context.Collections[$name]
        if ($collection -isnot [hashtable] -or $collection['Status'] -notin $script:CollectionStatuses) {
            throw "$where has collection '$name' without a valid Status ($($script:CollectionStatuses -join ', '))."
        }
        # JSON null/missing/single-object items normalized to an array.
        $collection.Items = @($collection['Items'] | Where-Object { $null -ne $_ })
        if (-not $collection.ContainsKey('Error')) { $collection.Error = $null }
    }
    $context
}
