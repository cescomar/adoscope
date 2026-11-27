function ConvertTo-AdoScopeSarifReport {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Report)

    $rules = @($Report.Rules | ForEach-Object { ConvertTo-AdoScopeSarifRule -Rule $_ })
    $hasBaseline = $null -ne $Report.Baseline
    $results = @($Report.Findings | ForEach-Object { ConvertTo-AdoScopeSarifResult -Finding $_ -Organization $Report.Organization -Rule $Report.Rules -HasBaseline:$hasBaseline })
    $notifications = @($Report.Checks | Where-Object Status -notin 'Evaluated', 'Disabled' |
            ForEach-Object { ConvertTo-AdoScopeSarifNotification -Check $_ })
    $run = [ordered]@{
        tool        = @{ driver = @{ name = 'adoscope'; semanticVersion = $Report.Version; rules = $rules } }
        results     = $results
        invocations = @(@{ executionSuccessful = $true; toolExecutionNotifications = $notifications })
    }
    [ordered]@{ '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'; version = '2.1.0'; runs = @($run) } |
        ConvertTo-Json -Depth 20
}

function ConvertTo-AdoScopeSarifRule {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)][pscustomobject]$Rule)

    [ordered]@{
        id                   = $Rule.Id
        name                 = ConvertTo-AdoScopePascalName -Text $Rule.Title
        shortDescription     = @{ text = $Rule.Title }
        fullDescription      = @{ text = $Rule.Rationale }
        help                 = @{ text = $Rule.Remediation }
        defaultConfiguration = @{ level = ConvertTo-AdoScopeSarifLevel -Severity $Rule.Severity }
        properties           = @{ category = $Rule.Category; tags = @($Rule.Category, 'azure-devops'); 'security-severity' = ConvertTo-AdoScopeSarifScore -Severity $Rule.Severity }
    }
}

function ConvertTo-AdoScopeSarifResult {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Finding,
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][object[]]$Rule,
        [switch]$HasBaseline
    )

    $index = [array]::FindIndex($Rule, [Predicate[object]]{ param($item) $item.Id -eq $Finding.CheckId })
    $project = if ($Finding.Project) { $Finding.Project } else { '_org' }
    $uri = 'ado://{0}/{1}/{2}' -f (ConvertTo-AdoScopeUriSegment $Organization), (ConvertTo-AdoScopeUriSegment $project), (ConvertTo-AdoScopeUriSegment $Finding.ResourceId)
    $result = [ordered]@{
        ruleId              = $Finding.CheckId
        ruleIndex           = $index
        level               = ConvertTo-AdoScopeSarifLevel -Severity $Finding.Severity
        message             = @{ text = $Finding.Detail }
        partialFingerprints = @{ 'adoscope/v1' = $Finding.Fingerprint }
        locations           = @(@{ physicalLocation = @{ artifactLocation = @{ uri = $uri } }; logicalLocations = @(@{ name = $Finding.Resource; fullyQualifiedName = "$project/$($Finding.Resource)"; kind = 'resource' }) })
    }
    if ($Finding.Suppressed) { $result['suppressions'] = @(@{ kind = 'external'; status = 'accepted'; justification = $Finding.SuppressionReason }) }
    if ($HasBaseline) { $result['baselineState'] = if ($Finding.InBaseline) { 'unchanged' } else { 'new' } }
    $result
}

function ConvertTo-AdoScopeSarifNotification {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][pscustomobject]$Check)

    @{ level = if ($Check.Status -eq 'Error') { 'error' } else { 'warning' }; message = @{ text = $Check.Message }; descriptor = @{ id = $Check.CheckId } }
}

function ConvertTo-AdoScopeSarifLevel {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Severity)

    if ($Severity -in 'Critical', 'High') { 'error' } elseif ($Severity -eq 'Medium') { 'warning' } else { 'note' }
}

function ConvertTo-AdoScopeSarifScore {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Severity)

    @{ Critical = '9.5'; High = '8.0'; Medium = '5.5'; Low = '3.0'; Info = '1.0' }[$Severity]
}

function ConvertTo-AdoScopePascalName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    (($Text -split '[^A-Za-z0-9]+') | Where-Object { $_ } | ForEach-Object { $_[0].ToString().ToUpperInvariant() + $_.Substring(1) }) -join ''
}

function ConvertTo-AdoScopeUriSegment {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Text)

    [System.Uri]::EscapeDataString($Text)
}
