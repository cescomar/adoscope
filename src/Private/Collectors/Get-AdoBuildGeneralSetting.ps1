function Get-AdoBuildGeneralSetting {
    <#
    .SYNOPSIS
        Effective pipeline settings of one project (org-level enforcement already applied),
        plus _project @{ id; name }. Only exists at project level (404 at org level).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project
    )

    $uri = Get-AdoScopeApiUri -Organization $Organization -Path "$($Project.id)/_apis/build/generalsettings" `
        -ApiVersion $script:PreviewApiVersion.BuildGeneralSettings
    $settings = (Invoke-AdoScopeRequest -Uri $uri -Auth $Auth).Content
    $settings._project = @{ id = $Project.id; name = $Project.name }
    $settings
}
