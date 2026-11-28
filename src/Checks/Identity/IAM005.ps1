@{
    Id          = 'IAM005'
    Title       = 'Organization not connected to Microsoft Entra ID'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-2')
    Severity    = 'Medium'
    Rationale   = 'Administrators sign in with personal Microsoft accounts, which exist only in organizations not connected to Entra ID. Then MFA, conditional access, sign-in risk policies and central offboarding cannot be enforced: each account is protected only by its owner''s own settings.'
    Remediation = 'Connect the organization to your Microsoft Entra ID tenant (Organization settings > Microsoft Entra), map existing users to work accounts, then enforce MFA and conditional access in Entra ID.'
    Requires    = @('AdminGroups')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        # origin msa = personal Microsoft account; Entra-backed organizations only contain Entra identities.
        $personal = @($Context.Collections.AdminGroups.Items | ForEach-Object { @($_['members']) } |
                Where-Object { $_ -is [hashtable] -and $_['origin'] -eq 'msa' } | ForEach-Object { $_.descriptor } | Sort-Object -Unique)
        if (-not $personal) { return }
        New-AdoScopeFinding -Resource $Context.Organization -ResourceId "$($Context.Organization)/identity-provider" `
            -Detail "$($personal.Count) administrator(s) sign in with a personal Microsoft account; the organization is not backed by Entra ID."
    }
}
