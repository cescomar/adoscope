@{
    Id          = 'IAM002'
    Title       = 'Inactive administrator'
    Category    = 'Identity'
    Severity    = 'High'
    Rationale   = 'An administrator account nobody uses keeps full rights: it typically belongs to someone who changed role or left, is rarely monitored, and is a prime target because a takeover goes unnoticed.'
    Remediation = 'Confirm with the owner and remove the account from the administrator groups (or from the organization). Use time-bound elevation, for example Entra ID Privileged Identity Management on the group, instead of standing admin rights.'
    Parameters  = @{ days = 90 }
    Requires    = @('AdminGroups', 'UserEntitlements')
    Test        = {
        param($Context, $Parameters)
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        $entitlementByDescriptor = @{}
        foreach ($e in $Context.Collections.UserEntitlements.Items) {
            $d = $e['user']?['descriptor']
            if ($d) { $entitlementByDescriptor[$d] = $e }
        }
        # One finding per person, listing every admin group they are in.
        $admins = [ordered]@{}
        foreach ($group in $Context.Collections.AdminGroups.Items) {
            foreach ($m in @($group['members'] | Where-Object { $_ -is [hashtable] -and $_['descriptor'] })) {
                if (-not $admins.Contains($m.descriptor)) { $admins[$m.descriptor] = @{ Member = $m; Groups = [System.Collections.Generic.List[string]]::new() } }
                $admins[$m.descriptor].Groups.Add([string]$group.principalName)
            }
        }
        foreach ($descriptor in $admins.Keys) {
            $entitlement = $entitlementByDescriptor[$descriptor]
            if (-not $entitlement) { continue }   # no license record (for example a service principal): last access unknown
            $last = $entitlement['lastAccessedDate'] -as [datetime]
            $never = -not $last -or $last.Year -le 1
            $since = if ($never) { $entitlement['dateCreated'] -as [datetime] } else { $last }
            if (-not $since) { continue }
            $days = [int]($now - $since.ToUniversalTime()).TotalDays
            if ($days -lt $Parameters.days) { continue }
            $member = $admins[$descriptor].Member
            $label = if ($member['principalName']) { $member.principalName } else { $descriptor }
            $when = if ($never) { "Never signed in (added $days days ago)" } else { "Last access $days days ago" }
            New-AdoScopeFinding -Resource $label -ResourceId $descriptor `
                -Detail "$when; threshold $($Parameters.days) days. Administrator in: $(($admins[$descriptor].Groups | Sort-Object) -join ', ')."
        }
    }
}
