Set-StrictMode -Version Latest

$script:Severities = @('Info', 'Low', 'Medium', 'High', 'Critical')
$script:CollectionStatuses = @('Ok', 'Partial', 'Failed', 'Forbidden')
$script:CheckRoot = Join-Path $PSScriptRoot 'src/Checks'
# Bump when a saved context or JSON report changes shape incompatibly.
$script:ContextSchemaVersion = 1
$script:ReportSchemaVersion = 1

$functionFiles = @(
    Get-ChildItem -Path (Join-Path $PSScriptRoot 'src/Private') -Filter '*.ps1' -Recurse
    Get-ChildItem -Path (Join-Path $PSScriptRoot 'src/Public') -Filter '*.ps1'
)
foreach ($file in $functionFiles) {
    . $file.FullName
}

Export-ModuleMember -Function (Get-ChildItem -Path (Join-Path $PSScriptRoot 'src/Public') -Filter '*.ps1').BaseName
