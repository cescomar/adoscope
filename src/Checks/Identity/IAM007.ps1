@{
    Id          = 'IAM007'
    Title       = 'Personal access token with a long lifetime'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-6')
    Severity    = 'Medium'
    Rationale   = 'The longer a token stays valid, the longer a leaked copy keeps working, usually without anyone noticing. Short lifetimes bound the damage of a leak and force a periodic review of who still needs access.'
    Remediation = 'Revoke the token and issue one with a lifetime of at most the configured maximum, renewing it when needed. Enable the "Enforce maximum personal access token lifespan" policy where available, and move automation to Microsoft Entra tokens or workload identity federation.'
    Parameters  = @{ maxDays = 90 }
    Requires    = @('PersonalAccessTokens')
    Test        = {
        param($Context, $Parameters)
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($token in $Context.Collections.PersonalAccessTokens.Items) {
            if ($token['_error'] -or $token['isValid'] -ne $true) { continue }
            $from = $token['validFrom'] -as [datetime]
            $to = $token['validTo'] -as [datetime]
            if (-not $from -or -not $to -or $to.ToUniversalTime() -lt $now) { continue }
            $days = [int]($to - $from).TotalDays
            if ($days -le $Parameters.maxDays) { continue }
            New-AdoScopeFinding -Resource "$($token.user)/$($token['displayName'])" -ResourceId $token.authorizationId `
                -Detail "Token '$($token['displayName'])' of $($token.user) is valid for $days days (until $($to.ToString('yyyy-MM-dd'))); maximum $($Parameters.maxDays)."
        }
    }
}
