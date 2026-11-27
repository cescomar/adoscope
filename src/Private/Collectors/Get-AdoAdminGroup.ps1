function Get-AdoAdminGroup {
    <#
    .SYNOPSIS
        Administrator groups with their effective members: Project Collection Administrators
        (scope organization) and each project's Project Administrators (scope project).
        Nested groups are expanded. Built-in service identities (origin vsts: build service,
        agent pool service; over 100 in a small organization) are dropped: they are platform
        plumbing, not people. Each member records the group it was reached through (via).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth
    )

    $groups = @{}
    $users = @{}
    $groupsUri = Get-AdoScopeApiUri -Organization $Organization -Path '_apis/graph/groups' -Service vssps -ApiVersion $script:PreviewApiVersion.Graph
    $usersUri = Get-AdoScopeApiUri -Organization $Organization -Path '_apis/graph/users' -Service vssps -ApiVersion $script:PreviewApiVersion.Graph
    foreach ($g in Invoke-AdoScopeListRequest -Uri $groupsUri -Auth $Auth) { $groups[$g.descriptor] = $g }
    foreach ($u in Invoke-AdoScopeListRequest -Uri $usersUri -Auth $Auth) { $users[$u.descriptor] = $u }

    foreach ($group in $groups.Values) {
        $name = [string]$group['principalName']
        $scope = $null
        if ($name -like '*\Project Collection Administrators') { $scope = 'organization' }
        elseif ($name -like '*\Project Administrators' -and [string]$group['domain'] -like '*/TeamProject/*') { $scope = 'project' }
        if (-not $scope) { continue }
        @{
            descriptor    = $group.descriptor
            principalName = $name
            scope         = $scope
            project       = if ($scope -eq 'project') { $name -replace '^\[(.+)\]\\.*$', '$1' } else { $null }
            members       = @(Get-AdoScopeGroupMember -Organization $Organization -Auth $Auth -Descriptor $group.descriptor -Group $groups -User $users)
        }
    }
}

function Get-AdoScopeGroupMember {
    <# Effective users of a group: breadth-first through nested groups, each group visited once. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Organization,
        [Parameter(Mandatory)][pscustomobject]$Auth,
        [Parameter(Mandatory)][string]$Descriptor,
        [Parameter(Mandatory)][hashtable]$Group,
        [Parameter(Mandatory)][hashtable]$User
    )

    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $queue = [System.Collections.Generic.Queue[object]]::new()
    $queue.Enqueue(@{ Descriptor = $Descriptor; Via = 'direct' })
    $found = [ordered]@{}
    while ($queue.Count) {
        $current = $queue.Dequeue()
        if (-not $visited.Add($current.Descriptor)) { continue }   # cycles and shared nested groups
        $uri = Get-AdoScopeApiUri -Organization $Organization -Path "_apis/graph/Memberships/$($current.Descriptor)" -Query @{ direction = 'down' } `
            -Service vssps -ApiVersion $script:PreviewApiVersion.Graph
        foreach ($membership in Invoke-AdoScopeListRequest -Uri $uri -Auth $Auth) {
            $d = [string]$membership['memberDescriptor']
            if ($d -match '^(vssgp|aadgp)\.') {
                $via = if ($Group.ContainsKey($d)) { [string]$Group[$d]['principalName'] } else { $d }
                $queue.Enqueue(@{ Descriptor = $d; Via = $via })
                continue
            }
            $u = $User[$d]
            if ($d -like 'svc.*' -or ($u -and $u['origin'] -eq 'vsts')) { continue }   # built-in service identity
            if ($found.Contains($d)) { continue }
            $found[$d] = @{
                descriptor    = $d
                displayName   = if ($u) { $u['displayName'] } else { $null }
                principalName = if ($u) { $u['principalName'] } else { $null }
                origin        = if ($u) { $u['origin'] } else { $null }
                subjectKind   = if ($u) { $u['subjectKind'] } else { $null }
                metaType      = if ($u) { $u['metaType'] } else { $null }
                via           = $current.Via
            }
        }
    }
    $found.Values
}
