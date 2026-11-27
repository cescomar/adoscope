@{
    Id          = 'CST001'
    Title       = 'Paid license assigned to an inactive user'
    Category    = 'Cost'
    Severity    = 'Medium'
    Rationale   = 'Basic and Basic + Test Plans licenses are billed monthly whether or not the user signs in; inactive accounts are also an access risk (leavers, forgotten guests).'
    Remediation = 'Confirm the user no longer needs access, then change the access level to Stakeholder (free) or remove the user in Organization settings > Users. Prefer group rules so licenses follow team membership.'
    # express = Basic, advanced = Basic + Test Plans. Visual Studio subscribers (licensingSource msdn) cost nothing extra and are skipped.
    Parameters  = @{ days = 90; licenseTypes = @('express', 'advanced') }
    Requires    = @('UserEntitlements')
    Test        = {
        param($Context, $Parameters)
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($entitlement in $Context.Collections.UserEntitlements.Items) {
            $level = $entitlement['accessLevel']
            if ($level -isnot [hashtable] -or $level['licensingSource'] -eq 'msdn' -or $level['accountLicenseType'] -notin $Parameters.licenseTypes) { continue }
            $last = $entitlement['lastAccessedDate'] -as [datetime]
            $never = -not $last -or $last.Year -le 1
            $since = if ($never) { $entitlement['dateCreated'] -as [datetime] } else { $last }
            if (-not $since) { continue }
            $days = [int]($now - $since.ToUniversalTime()).TotalDays
            if ($days -lt $Parameters.days) { continue }
            $user = $entitlement['user']
            $label = if ($user -is [hashtable] -and $user['principalName']) { $user.principalName } else { [string]$entitlement.id }
            $detail = if ($never) { "Never signed in; license assigned $days days ago." } else { "Last access $days days ago." }
            New-AdoScopeFinding -Resource $label -ResourceId ([string]$entitlement.id) `
                -Detail "$detail License: $($level['licenseDisplayName'] ?? $level['accountLicenseType']); threshold $($Parameters.days) days."
        }
    }
}
