@{
    Id          = 'IAM006'
    Title       = 'Personal access token with full access'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-6')
    Severity    = 'High'
    Rationale   = 'A full-access token (scope "app_token") can do everything its owner can: read and change code, pipelines, service connections and permissions. Tokens leak through scripts, logs, chats and laptops; a full-access one turns a leak into a takeover of the account''s rights.'
    Remediation = 'Revoke the token and create a replacement with only the scopes the use case needs (for example Code Read or Build Read & execute) and the shortest practical expiry. Prefer Microsoft Entra tokens or workload identity federation for automation, and enable the "Restrict creation of full-scoped PATs" policy where available.'
    Requires    = @('PersonalAccessTokens')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($token in $Context.Collections.PersonalAccessTokens.Items) {
            if ($token['_error'] -or $token['isValid'] -ne $true -or $token['scope'] -ne 'app_token') { continue }
            $validTo = $token['validTo'] -as [datetime]
            if ($validTo -and $validTo.ToUniversalTime() -lt $now) { continue }   # already expired
            $until = if ($validTo) { $validTo.ToString('yyyy-MM-dd') } else { 'an unknown date' }
            New-AdoScopeFinding -Resource "$($token.user)/$($token['displayName'])" -ResourceId $token.authorizationId `
                -Detail "Token '$($token['displayName'])' of $($token.user) has full access; valid until $until."
        }
    }
}
