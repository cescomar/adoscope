@{
    Id          = 'SEC008'
    Title       = 'Variable group with secrets authorized for all pipelines'
    Category    = 'Security'
    Severity    = 'High'
    Rationale   = 'Every pipeline in the project, including one created from a feature branch, can read the secrets of this variable group without approval. Anyone who can edit a pipeline can print or exfiltrate them.'
    Remediation = 'In Pipelines > Library > the variable group > Pipeline permissions, remove "open access" and authorize only the pipelines that need it. Add approvals for production secrets, or link the group to Azure Key Vault with restricted access.'
    Requires    = @('VariableGroups')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($group in $Context.Collections.VariableGroups.Items) {
            $all = $group['_pipelinePermissions']?['allPipelines']
            if (-not ($all -and $all['authorized'] -eq $true)) { continue }
            $variables = if ($group['variables'] -is [hashtable]) { $group.variables } else { @{} }
            $sensitive = @($variables.Keys | Where-Object { $variables[$_]?['isSecret'] -eq $true -or $variables[$_]?['_valueLooksLikeCredential'] -eq $true })
            # Without secrets an open group is a convenience, not a risk.
            if ($group['type'] -ne 'AzureKeyVault' -and -not $sensitive) { continue }
            $what = if ($group['type'] -eq 'AzureKeyVault') { 'Key Vault-linked secrets' } else { "secret(s): $(($sensitive | Sort-Object) -join ', ')" }
            New-AdoScopeFinding -Project $group['_project']?['name'] -Resource $group.name -ResourceId ([string]$group.id) `
                -Detail "Variable group '$($group.name)' is open to every pipeline and holds $what."
        }
    }
}
