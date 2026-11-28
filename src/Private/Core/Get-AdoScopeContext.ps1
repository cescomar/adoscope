# Collection name -> collector. Projects is collected first by Get-AdoScopeContext.
$script:ProjectCollectors = [ordered]@{
    BuildDefinitions     = 'Get-AdoBuildDefinition'
    Builds               = 'Get-AdoBuild'
    BuildGeneralSettings = 'Get-AdoBuildGeneralSetting'
    ServiceConnections   = 'Get-AdoServiceConnection'
    VariableGroups       = 'Get-AdoVariableGroup'
    SecureFiles          = 'Get-AdoSecureFile'
    Environments         = 'Get-AdoEnvironment'
    Repositories         = 'Get-AdoRepository'
    RepositoryActivity   = 'Get-AdoRepositoryActivity'
    Policies             = 'Get-AdoPolicy'
    AgentQueues          = 'Get-AdoAgentQueue'
    ReleaseDefinitions   = 'Get-AdoReleaseDefinition'
}
# Organization-wide; not affected by -Project.
$script:OrganizationCollectors = [ordered]@{
    AgentPools       = 'Get-AdoAgentPool'
    UserEntitlements = 'Get-AdoUserEntitlement'
    AdminGroups      = 'Get-AdoAdminGroup'
}

function Get-AdoScopeContext {
    <#
    .SYNOPSIS
        Collects the requested collections from the live organization into a context
        (shape: see Import-AdoScopeContext). A failing project makes the collection
        Partial; failing everywhere makes it Forbidden (all 401/403) or Failed.
        Projects are collected ThrottleLimit at a time; results are merged in project
        order, so the context does not depend on which project finished first.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Collection,
        # Restrict to these project names; all projects when empty.
        [string[]]$Project,
        [ValidateRange(1, 16)][int]$ThrottleLimit = 1
    )

    $context = @{ Organization = $Organization; CollectedAt = [datetime]::UtcNow; Collections = @{} }
    # Auth failures surface here and are terminating: nothing else would work.
    $projects = @(Get-AdoProject -Organization $Organization -Auth $Auth)
    if ($Project) {
        $unknown = @($Project | Where-Object { $_ -notin $projects.name })
        if ($unknown) { throw "Unknown project(s) in organization '$Organization': $($unknown -join ', ')." }
        $projects = @($projects | Where-Object { $_.name -in $Project })
    }
    $context.Collections.Projects = @{ Status = 'Ok'; Items = $projects; Error = $null }

    $names = @($script:ProjectCollectors.Keys | Where-Object { $_ -in $Collection })
    if ($names -and $projects) {
        $byProject = @{}
        foreach ($outcome in Invoke-AdoScopeProjectBatch -Organization $Organization -Auth $Auth -Project $projects -Collection $names -ThrottleLimit $ThrottleLimit) {
            $byProject[$outcome.Project] = $outcome.Data
            Write-Progress -Activity 'adoscope: collecting' -Status "$($byProject.Count) of $($projects.Count) projects ($($outcome.Project))" `
                -PercentComplete ([int](100 * $byProject.Count / $projects.Count))
        }
        Write-Progress -Activity 'adoscope: collecting' -Completed
        foreach ($name in $names) {
            $data = @($projects | ForEach-Object { $byProject[$_.name][$name] })
            $context.Collections[$name] = ConvertTo-AdoScopeCollection -Name $name -Item @($data | ForEach-Object { $_.Items }) -Failure @($data | ForEach-Object { $_.Errors })
        }
    }

    foreach ($name in $script:OrganizationCollectors.Keys | Where-Object { $_ -in $Collection }) {
        Write-Progress -Activity 'adoscope: collecting' -Status "organization: $name"
        try {
            $items = @(& $script:OrganizationCollectors[$name] -Organization $Organization -Auth $Auth)
            $context.Collections[$name] = ConvertTo-AdoScopeCollection -Name $name -Item $items -Failure @()
        }
        catch {
            $failure = [pscustomobject]@{ Project = '(organization)'; Exception = $_.Exception }
            $context.Collections[$name] = ConvertTo-AdoScopeCollection -Name $name -Item @() -Failure $failure
        }
    }
    Write-Progress -Activity 'adoscope: collecting' -Completed
    $context
}

function Invoke-AdoScopeProjectBatch {
    <#
    .SYNOPSIS
        Emits one Get-AdoScopeProjectData outcome per project, in completion order:
        sequentially, or from up to ThrottleLimit parallel runspaces.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable[]]$Project,
        [Parameter(Mandatory)][string[]]$Collection,
        [int]$ThrottleLimit = 1
    )

    if ($ThrottleLimit -le 1 -or $Project.Count -le 1) {
        foreach ($p in $Project) { Get-AdoScopeProjectData -Organization $Organization -Auth $Auth -Project $p -Collection $Collection }
        return
    }
    $manifest = Join-Path $MyInvocation.MyCommand.Module.ModuleBase 'adoscope.psd1'
    # Each runspace gets its own credential copy (SecureString is not thread-safe); copies are made here, on one thread.
    $work = foreach ($p in $Project) { @{ Project = $p; Auth = Copy-AdoScopeAuth -Auth $Auth } }
    $work | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        # Runspaces are reused across items, so the module is imported once per runspace.
        if (-not (Get-Module adoscope)) { Import-Module $using:manifest }
        # Runs inside the module scope (private functions); arguments: organization, auth, project, collections.
        & (Get-Module adoscope) {
            Get-AdoScopeProjectData -Organization $args[0] -Auth $args[1] -Project $args[2] -Collection $args[3]
        } $using:Organization $_.Auth $_.Project $using:Collection
    }
}

function Get-AdoScopeProjectData {
    <#
    .SYNOPSIS
        Runs the requested project collectors for one project. Never throws: failures
        (whole collector or one item via _error) are returned per collection.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][hashtable]$Project,
        [Parameter(Mandatory)][string[]]$Collection
    )

    $data = @{}
    foreach ($name in $Collection) {
        $items = [System.Collections.Generic.List[object]]::new()
        $errors = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($item in & $script:ProjectCollectors[$name] -Organization $Organization -Auth $Auth -Project $Project) {
                $items.Add($item)
                # A failed secondary call marks only its item (Add-AdoScopeEnrichment).
                if ($item -is [hashtable] -and $item['_error']) {
                    $errors.Add([pscustomobject]@{ Project = $Project.name; Exception = [System.Exception]::new($item._error) })
                }
            }
        }
        catch { $errors.Add([pscustomobject]@{ Project = $Project.name; Exception = $_.Exception }) }
        $data[$name] = @{ Items = $items.ToArray(); Errors = $errors.ToArray() }
    }
    [pscustomobject]@{ Project = $Project.name; Data = $data }
}

function ConvertTo-AdoScopeCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Item,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Failure
    )

    if (-not $Failure) { return @{ Status = 'Ok'; Items = $Item; Error = $null } }

    $message = Protect-AdoScopeText (($Failure | ForEach-Object { "$($_.Project): $($_.Exception.Message)" }) -join ' | ')
    Write-Warning "Collection $Name incomplete: $message"
    $denied = @($Failure | Where-Object {
            $code = $_.Exception.PSObject.Properties['StatusCode']?.Value
            $code -in [System.Net.HttpStatusCode]::Forbidden, [System.Net.HttpStatusCode]::Unauthorized
        })
    $status = if ($Item) { 'Partial' } elseif ($denied.Count -eq $Failure.Count) { 'Forbidden' } else { 'Failed' }
    @{ Status = $status; Items = $Item; Error = $message }
}
