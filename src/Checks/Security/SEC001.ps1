@{
    Id          = 'SEC001'
    Title       = 'Service connection authorized for all pipelines'
    Category    = 'Security'
    Standards   = @('CICD-SEC-5')
    Severity    = 'High'
    Rationale   = 'Any pipeline in the project, including one created tomorrow from a feature branch, can use the credential without an approval, so anyone who can edit a pipeline can act with its permissions.'
    Remediation = 'In Project settings > Service connections > Security, disable "Grant access permission to all pipelines" and authorize only the pipelines that need it. Add approvals and checks for production connections.'
    Requires    = @('ServiceConnections')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($endpoint in $Context.Collections.ServiceConnections.Items) {
            $all = $endpoint['_pipelinePermissions']?['allPipelines']
            if ($all -and $all['authorized'] -eq $true) {
                New-AdoScopeFinding -Project $endpoint['_project']?['name'] -Resource $endpoint.name -ResourceId $endpoint.id `
                    -Detail "Service connection '$($endpoint.name)' (type $($endpoint['type'])) is open to every pipeline in the project."
            }
        }
    }
}
