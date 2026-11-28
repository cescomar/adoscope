#Requires -Version 7.2
<#
.SYNOPSIS
    Creates a disposable 'adoscope-lab' project with known-good and known-bad resources,
    so every adoscope check has something to find on a live organization.

.DESCRIPTION
    THIS SCRIPT WRITES TO THE ORGANIZATION. It is a development aid, not part of the
    adoscope module (which is read-only). Everything is created inside one new project;
    delete that project to remove it all. Idempotent: existing items are reused.

    All identifiers and secrets below are synthetic. Service connections are created in
    Manual mode and never contact Azure.

    Requires a PAT in $env:AZURE_DEVOPS_EXT_PAT with rights to create projects, pipelines,
    service connections and change pipeline settings.

.EXAMPLE
    ./lab/Initialize-AdoScopeLab.ps1 -Organization fabrikam -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Organization,
    [string]$ProjectName = 'adoscope-lab'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $env:AZURE_DEVOPS_EXT_PAT) { throw 'Set $env:AZURE_DEVOPS_EXT_PAT first.' }
$base = "https://dev.azure.com/$Organization"
$authHeader = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$env:AZURE_DEVOPS_EXT_PAT"))
$fake = @{ Tenant = '11111111-1111-1111-1111-111111111111'; Client = '22222222-2222-2222-2222-222222222222'; Subscription = '33333333-3333-3333-3333-333333333333' }

function Invoke-LabApi([string]$Method, [string]$Path, [string]$Version = '7.1', [object]$Body) {
    $separator = if ($Path.Contains('?')) { '&' } else { '?' }
    $params = @{ Method = $Method; Uri = "$base/$Path${separator}api-version=$Version"; Headers = @{ Authorization = $authHeader } }
    if ($null -ne $Body) { $params.Body = $Body | ConvertTo-Json -Depth 20; $params.ContentType = 'application/json' }
    Invoke-RestMethod @params
}

function Initialize-LabProject {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $existing = @((Invoke-LabApi GET '_apis/projects').value | Where-Object name -eq $ProjectName)
    if ($existing) { return Invoke-LabApi GET "_apis/projects/$($existing[0].id)" }
    if (-not $PSCmdlet.ShouldProcess($ProjectName, 'Create project')) { return $null }
    $basicProcess = ((Invoke-LabApi GET '_apis/process/processes').value | Where-Object isDefault)[0].id
    $op = Invoke-LabApi POST '_apis/projects' -Body @{
        name = $ProjectName; description = 'adoscope test lab - safe to delete'; visibility = 'private'
        capabilities = @{ versioncontrol = @{ sourceControlType = 'Git' }; processTemplate = @{ templateTypeId = $basicProcess } }
    }
    do { Start-Sleep -Seconds 2; $status = (Invoke-LabApi GET "_apis/operations/$($op.id)").status } while ($status -in 'notSet', 'queued', 'inProgress')
    if ($status -ne 'succeeded') { throw "Project creation ended with status '$status'." }
    Invoke-LabApi GET "_apis/projects/$ProjectName"
}

function Initialize-LabRepository {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $repo = Invoke-LabApi GET "$($Project.id)/_apis/git/repositories/$ProjectName"
    if ($repo.PSObject.Properties['defaultBranch'] -and $repo.defaultBranch) { return $repo }
    if (-not $PSCmdlet.ShouldProcess($repo.name, 'Push azure-pipelines.yml')) { return $repo }
    $yaml = "trigger: none`npool:`n  vmImage: ubuntu-latest`nsteps:`n- script: echo adoscope lab`n"
    $null = Invoke-LabApi POST "$($Project.id)/_apis/git/repositories/$($repo.id)/pushes" -Body @{
        refUpdates = @(@{ name = 'refs/heads/main'; oldObjectId = '0' * 40 })
        commits    = @(@{ comment = 'adoscope lab'; changes = @(@{ changeType = 'add'; item = @{ path = '/azure-pipelines.yml' }; newContent = @{ content = $yaml; contentType = 'rawtext' } }) })
    }
    Invoke-LabApi GET "$($Project.id)/_apis/git/repositories/$($repo.id)"
}

function Set-LabWeakSetting {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    # Weakened on purpose: SEC005 must report these. Org-level policies may override them.
    if (-not $PSCmdlet.ShouldProcess($ProjectName, 'Weaken pipeline general settings')) { return }
    Invoke-LabApi PATCH "$($Project.id)/_apis/build/generalsettings" -Version '7.1-preview.1' -Body @{
        enforceJobAuthScope = $false; enforceSettableVar = $false; statusBadgesArePrivate = $false
        disableClassicPipelineCreation = $false; disableClassicBuildPipelineCreation = $false
    }
}

function Initialize-LabPipeline {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project, $Repo)
    $names = @((Invoke-LabApi GET "$($Project.id)/_apis/build/definitions").value | ForEach-Object name)
    if ('lab-yaml' -notin $names -and $PSCmdlet.ShouldProcess('lab-yaml', 'Create YAML pipeline')) {
        $null = Invoke-LabApi POST "$($Project.id)/_apis/pipelines" -Body @{
            name = 'lab-yaml'; folder = '\'
            configuration = @{ type = 'yaml'; path = '/azure-pipelines.yml'; repository = @{ id = $Repo.id; name = $Repo.name; type = 'azureReposGit' } }
        }
    }
    if ('lab-classic' -notin $names -and $PSCmdlet.ShouldProcess('lab-classic', 'Create classic pipeline')) {
        $queue = @((Invoke-LabApi GET "$($Project.id)/_apis/distributedtask/queues?queueName=Azure%20Pipelines").value)[0]
        $body = @{
            name = 'lab-classic'; type = 'build'; quality = 'definition'; queue = @{ id = $queue.id }; jobAuthorizationScope = 'projectCollection'
            repository = @{ id = $Repo.id; name = $Repo.name; type = 'TfsGit'; defaultBranch = 'refs/heads/main' }
            process = @{ type = 1; phases = @(@{ name = 'Job 1'; refName = 'Job_1'; condition = 'succeeded()'; steps = @(); jobAuthorizationScope = 'projectCollection'
                        target = @{ type = 1; executionOptions = @{ type = 0 }; allowScriptsAuthAccessOption = $false } }) }
        }
        # Fails when the organization disables classic pipelines (secure default); enable it in
        # Organization settings > Pipelines > Settings and rerun to get a PIP003 finding.
        try { $null = Invoke-LabApi POST "$($Project.id)/_apis/build/definitions" -Body $body }
        catch { Write-Warning "lab-classic not created: $($_.ErrorDetails.Message ?? $_.Exception.Message)" }
    }
}

function Set-LabPipelineVariable {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $id = @((Invoke-LabApi GET "$($Project.id)/_apis/build/definitions?name=lab-yaml").value)[0].id
    $definition = Invoke-LabApi GET "$($Project.id)/_apis/build/definitions/$id"
    if ($definition.PSObject.Properties['variables'] -and $definition.variables.PSObject.Properties['LabDeployToken']) { return }
    if (-not $PSCmdlet.ShouldProcess('lab-yaml', 'Add pipeline variables')) { return }
    # Credential-shaped synthetic value (legacy PAT format) as a plain pipeline variable on purpose: SEC011.
    $variables = @{
        LabDeployToken = @{ value = ('labp2345' * 6 + 'labp'); isSecret = $false }
        LabRegion      = @{ value = 'westeurope'; isSecret = $false }
    }
    $definition | Add-Member -NotePropertyName variables -NotePropertyValue $variables -Force
    $null = Invoke-LabApi PUT "$($Project.id)/_apis/build/definitions/$id" -Body $definition
    Write-Output 'added plain-text variables to lab-yaml'
}

function Initialize-LabServiceConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $existing = @((Invoke-LabApi GET "$($Project.id)/_apis/serviceendpoint/endpoints").value | ForEach-Object name)
    $data = @{ subscriptionId = $fake.Subscription; subscriptionName = 'adoscope-lab-fake'; environment = 'AzureCloud'; scopeLevel = 'Subscription'; creationMode = 'Manual' }
    $definitions = @(
        @{ name = 'lab-azurerm-secret'; type = 'azurerm'; url = 'https://management.azure.com/'; data = $data; allPipelines = $true
            authorization = @{ scheme = 'ServicePrincipal'; parameters = @{ tenantid = $fake.Tenant; serviceprincipalid = $fake.Client; authenticationType = 'spnKey'; serviceprincipalkey = 'synthetic-not-a-secret' } } }
        @{ name = 'lab-azurerm-certificate'; type = 'azurerm'; url = 'https://management.azure.com/'; data = $data; allPipelines = $false
            authorization = @{ scheme = 'ServicePrincipal'; parameters = @{ tenantid = $fake.Tenant; serviceprincipalid = $fake.Client; authenticationType = 'spnCertificate'; servicePrincipalCertificate = "-----BEGIN CERTIFICATE-----`nc3ludGhldGlj`n-----END CERTIFICATE-----" } } }
        @{ name = 'lab-azurerm-wif'; type = 'azurerm'; url = 'https://management.azure.com/'; data = $data; allPipelines = $false
            authorization = @{ scheme = 'WorkloadIdentityFederation'; parameters = @{ tenantid = $fake.Tenant; serviceprincipalid = $fake.Client } } }
        @{ name = 'lab-generic'; type = 'generic'; url = 'https://example.invalid/'; data = @{}; allPipelines = $true
            authorization = @{ scheme = 'UsernamePassword'; parameters = @{ username = 'lab'; password = 'synthetic-not-a-secret' } } }
    )
    foreach ($d in $definitions | Where-Object { $_.name -notin $existing }) {
        if (-not $PSCmdlet.ShouldProcess($d.name, 'Create service connection')) { continue }
        $endpoint = Invoke-LabApi POST '_apis/serviceendpoint/endpoints' -Body @{
            name = $d.name; type = $d.type; url = $d.url; data = $d.data; authorization = $d.authorization; isShared = $false; owner = 'library'
            serviceEndpointProjectReferences = @(@{ name = $d.name; projectReference = @{ id = $Project.id; name = $Project.name } })
        }
        if ($d.allPipelines) {
            # Open to every pipeline on purpose: SEC001 must report these.
            $null = Invoke-LabApi PATCH "$($Project.id)/_apis/pipelines/pipelinePermissions/endpoint/$($endpoint.id)" -Version '7.1-preview.1' -Body @{ allPipelines = @{ authorized = $true } }
        }
        Write-Output "created service connection $($d.name)"
    }
}

function Initialize-LabLibrary {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $groups = @((Invoke-LabApi GET "$($Project.id)/_apis/distributedtask/variablegroups").value | ForEach-Object name)
    $definitions = @(
        # Secret behind open access: SEC008.
        @{ name = 'lab-vg-secrets'; open = $true; variables = @{ DbPassword = @{ value = 'synthetic-not-a-secret'; isSecret = $true } } }
        # Credential-shaped synthetic value (legacy PAT format) left in plain text on purpose: SEC009.
        @{ name = 'lab-vg-plain'; open = $false; variables = @{ ApiToken = @{ value = ('labx2345' * 6 + 'labx') }; Region = @{ value = 'westeurope' } } }
    )
    foreach ($d in $definitions | Where-Object { $_.name -notin $groups }) {
        if (-not $PSCmdlet.ShouldProcess($d.name, 'Create variable group')) { continue }
        $group = Invoke-LabApi POST '_apis/distributedtask/variablegroups' -Body @{
            name = $d.name; type = 'Vsts'; variables = $d.variables
            variableGroupProjectReferences = @(@{ name = $d.name; projectReference = @{ id = $Project.id; name = $Project.name } })
        }
        if ($d.open) {
            $null = Invoke-LabApi PATCH "$($Project.id)/_apis/pipelines/pipelinePermissions/variablegroup/$($group.id)" -Version '7.1-preview.1' -Body @{ allPipelines = @{ authorized = $true } }
        }
        Write-Output "created variable group $($d.name)"
    }
    $files = @((Invoke-LabApi GET "$($Project.id)/_apis/distributedtask/securefiles").value | ForEach-Object name)
    if ('lab-signing.pfx' -notin $files -and $PSCmdlet.ShouldProcess('lab-signing.pfx', 'Upload secure file open to all pipelines')) {
        # Not a certificate: placeholder bytes. Open access on purpose: SEC010.
        $file = Invoke-RestMethod -Method POST -Uri "$base/$($Project.id)/_apis/distributedtask/securefiles?name=lab-signing.pfx&api-version=7.1-preview.1" `
            -Headers @{ Authorization = $authHeader } -ContentType 'application/octet-stream' -Body ([Text.Encoding]::ASCII.GetBytes('synthetic placeholder'))
        $null = Invoke-LabApi PATCH "$($Project.id)/_apis/pipelines/pipelinePermissions/securefile/$($file.id)" -Version '7.1-preview.1' -Body @{ allPipelines = @{ authorized = $true } }
        Write-Output 'created secure file lab-signing.pfx'
    }
}

function Initialize-LabEnvironment {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $existing = @((Invoke-LabApi GET "$($Project.id)/_apis/distributedtask/environments").value | ForEach-Object name)
    $me = (Invoke-LabApi GET '_apis/connectionData' -Version '7.1-preview.1').authenticatedUser.id
    foreach ($name in @('production', 'prod-approved') | Where-Object { $_ -notin $existing }) {
        if (-not $PSCmdlet.ShouldProcess($name, 'Create environment')) { continue }
        $environment = Invoke-LabApi POST "$($Project.id)/_apis/distributedtask/environments" -Body @{ name = $name; description = 'adoscope lab' }
        Write-Output "created environment $name"
        if ($name -ne 'prod-approved') { continue }   # 'production' stays unprotected: PIP001 and PIP002
        $resource = @{ type = 'environment'; id = [string]$environment.id; name = $name }
        $null = Invoke-LabApi POST "$($Project.id)/_apis/pipelines/checks/configurations" -Version '7.1-preview.1' -Body @{
            type = @{ id = '8c6f20a7-a545-4486-9777-f762fafe0d4d'; name = 'Approval' }; resource = $resource; timeout = 43200
            settings = @{ approvers = @(@{ id = $me }); executionOrder = 'anyOrder'; minRequiredApprovers = 0; instructions = 'adoscope lab'; blockedApprovers = @() }
        }
        $null = Invoke-LabApi POST "$($Project.id)/_apis/pipelines/checks/configurations" -Version '7.1-preview.1' -Body @{
            type = @{ id = '4020e66e-b0f3-47e1-bc88-48f3cc59b5f3'; name = 'ExtendsCheck' }; resource = $resource; timeout = 43200
            settings = @{ extendsChecks = @(@{ repositoryType = 'git'; repositoryName = "$($Project.name)/$($Project.name)"; repositoryRef = 'refs/heads/main'; templatePath = 'templates/deploy.yml' }) }
        }
    }
}

function Initialize-LabProtectedRepository {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $names = @((Invoke-LabApi GET "$($Project.id)/_apis/git/repositories").value | ForEach-Object name)
    if ('lab-protected' -in $names -or -not $PSCmdlet.ShouldProcess('lab-protected', 'Create repository with reviewer policy')) { return }
    $repo = Invoke-LabApi POST "$($Project.id)/_apis/git/repositories" -Body @{ name = 'lab-protected'; project = @{ id = $Project.id } }
    $null = Invoke-LabApi POST "$($Project.id)/_apis/git/repositories/$($repo.id)/pushes" -Body @{
        refUpdates = @(@{ name = 'refs/heads/main'; oldObjectId = '0' * 40 })
        commits    = @(@{ comment = 'adoscope lab'; changes = @(@{ changeType = 'add'; item = @{ path = '/README.md' }; newContent = @{ content = '# protected'; contentType = 'rawtext' } }) })
    }
    # Compliant on purpose: SEC003 must NOT flag this repository (the default lab repository has no policy).
    $null = Invoke-LabApi POST "$($Project.id)/_apis/policy/configurations" -Body @{
        isEnabled = $true; isBlocking = $true; type = @{ id = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' }
        settings  = @{ minimumApproverCount = 2; creatorVoteCounts = $false; allowDownvotes = $false; resetOnSourcePush = $true
            scope = @(@{ repositoryId = $repo.id; refName = 'refs/heads/main'; matchKind = 'exact' }) }
    }
    Write-Output 'created repository lab-protected with a 2-reviewer policy'
}

function Initialize-LabRelease {
    [CmdletBinding(SupportsShouldProcess)]
    param($Project)
    $vsrm = "https://vsrm.dev.azure.com/$Organization/$($Project.id)/_apis/release/definitions"
    $existing = @((Invoke-RestMethod "${vsrm}?api-version=7.1" -Headers @{ Authorization = $authHeader }).value | ForEach-Object name)
    if ('lab-release' -in $existing -or -not $PSCmdlet.ShouldProcess('lab-release', 'Create classic release')) { return }
    $queueId = @((Invoke-LabApi GET "$($Project.id)/_apis/distributedtask/queues?queueName=Azure%20Pipelines").value)[0].id
    $me = (Invoke-LabApi GET '_apis/connectionData' -Version '7.1-preview.1').authenticatedUser.id
    $stage = {
        param($Name, $Rank, $Approvals, $Options)
        @{
            name = $Name; rank = $Rank; variables = @{}; conditions = @(); owner = @{ id = $me }
            retentionPolicy = @{ daysToKeep = 30; releasesToKeep = 3; retainBuild = $true }
            preDeployApprovals = @{ approvals = $Approvals; approvalOptions = $Options }
            postDeployApprovals = @{ approvals = @(@{ rank = 1; isAutomated = $true; isNotificationOn = $false }) }
            deployPhases = @(@{ rank = 1; phaseType = 'agentBasedDeployment'; name = 'Run on agent'; workflowTasks = @()
                    deploymentInput = @{ queueId = $queueId } })
        }
    }
    # Production: automatic approval only (PIP004). prod-eu: the release creator may approve (PIP005).
    # DeployPassword: credential-shaped synthetic value in plain text (SEC012).
    $body = @{
        name = 'lab-release'; path = '\'; releaseNameFormat = 'Release-$(rev:r)'
        variables = @{ DeployPassword = @{ value = ('labr2345' * 6 + 'labr'); isSecret = $false } }
        environments = @(
            (& $stage 'Production' 1 @(@{ rank = 1; isAutomated = $true; isNotificationOn = $false }) @{ releaseCreatorCanBeApprover = $false })
            (& $stage 'prod-eu' 2 @(@{ rank = 1; isAutomated = $false; isNotificationOn = $false; approver = @{ id = $me } }) @{ releaseCreatorCanBeApprover = $true; requiredApproverCount = 0; executionOrder = 'beforeGates' })
        )
    }
    try {
        $null = Invoke-RestMethod "${vsrm}?api-version=7.1" -Method Post -Headers @{ Authorization = $authHeader } -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 20)
        Write-Output 'created classic release lab-release'
    }
    catch { Write-Warning "lab-release not created (classic release creation disabled?): $($_.ErrorDetails.Message ?? $_.Exception.Message)" }
}

$project = Initialize-LabProject
if (-not $project) { return }
Write-Output "project: $($project.name) ($($project.id))"
$repo = Initialize-LabRepository $project
Set-LabWeakSetting $project | Out-Null
Initialize-LabPipeline $project $repo
Set-LabPipelineVariable $project
Initialize-LabServiceConnection $project
Initialize-LabLibrary $project
Initialize-LabEnvironment $project
Initialize-LabProtectedRepository $project
Initialize-LabRelease $project
Write-Output "lab ready - delete project '$ProjectName' to remove everything"
