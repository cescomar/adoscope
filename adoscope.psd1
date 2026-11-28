@{
    RootModule           = 'adoscope.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = '24e33732-1908-4d09-b414-f3911ca22fab'
    Author               = 'Francesco Marotta'
    Copyright            = '(c) 2026 Francesco Marotta. MIT License.'
    Description          = 'Read-only audit of an Azure DevOps Services organization: security, governance, hygiene and cost findings.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @('Invoke-AdoScope')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('AzureDevOps', 'Security', 'Audit', 'Governance', 'DevOps')
            ProjectUri = 'https://github.com/cescomar/adoscope'
            LicenseUri = 'https://github.com/cescomar/adoscope/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/cescomar/adoscope/blob/main/CHANGELOG.md'
        }
    }
}
