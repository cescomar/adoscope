@{
    Id          = 'IAM008'
    Title       = 'Personal access token valid in all organizations'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-6')
    Severity    = 'Medium'
    Rationale   = 'A token created for "All accessible organizations" works in every Azure DevOps organization its owner belongs to. A leak from one context exposes organizations this audit does not even cover.'
    Remediation = 'Revoke the token and create a replacement limited to this organization. Encourage users to select a single organization when creating tokens.'
    Requires    = @('PersonalAccessTokens')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $now = ([datetime]$Context.CollectedAt).ToUniversalTime()
        foreach ($token in $Context.Collections.PersonalAccessTokens.Items) {
            if ($token['_error'] -or $token['isValid'] -ne $true -or $token['allOrganizations'] -ne $true) { continue }
            $validTo = $token['validTo'] -as [datetime]
            if ($validTo -and $validTo.ToUniversalTime() -lt $now) { continue }
            New-AdoScopeFinding -Resource "$($token.user)/$($token['displayName'])" -ResourceId $token.authorizationId `
                -Detail "Token '$($token['displayName'])' of $($token.user) works in every organization the user can access."
        }
    }
}
