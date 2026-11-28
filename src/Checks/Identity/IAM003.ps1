@{
    Id          = 'IAM003'
    Title       = 'Guest account with administrator rights'
    Category    = 'Identity'
    Standards   = @('CICD-SEC-2')
    Severity    = 'High'
    Rationale   = 'A guest (Entra ID B2B) account is managed by another organization: its password, MFA and offboarding are outside your control. With administrator rights, a compromise or a missed offboarding on their side gives full control of your Azure DevOps.'
    Remediation = 'Remove guest accounts from administrator groups. If an external partner needs elevated access, grant the narrowest project role, time-bound, and review it regularly; consider disabling "External guest access" in Organization settings > Policies.'
    Requires    = @('AdminGroups')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $guests = [ordered]@{}
        foreach ($group in $Context.Collections.AdminGroups.Items) {
            foreach ($m in @($group['members'] | Where-Object { $_ -is [hashtable] -and $_['metaType'] -eq 'guest' })) {
                if (-not $guests.Contains($m.descriptor)) { $guests[$m.descriptor] = @{ Member = $m; Groups = [System.Collections.Generic.List[string]]::new() } }
                $guests[$m.descriptor].Groups.Add([string]$group.principalName)
            }
        }
        foreach ($descriptor in $guests.Keys) {
            $member = $guests[$descriptor].Member
            $label = if ($member['principalName']) { $member.principalName } else { $descriptor }
            New-AdoScopeFinding -Resource $label -ResourceId $descriptor `
                -Detail "Guest account is administrator in: $(($guests[$descriptor].Groups | Sort-Object) -join ', ')."
        }
    }
}
