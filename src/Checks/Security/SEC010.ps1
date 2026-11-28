@{
    Id          = 'SEC010'
    Title       = 'Secure file authorized for all pipelines'
    Category    = 'Security'
    Standards   = @('CICD-SEC-5')
    Severity    = 'High'
    Rationale   = 'Secure files hold signing certificates, provisioning profiles and keys. Open to every pipeline, any pipeline author can download them and sign or publish as the organization.'
    Remediation = 'In Pipelines > Library > Secure files > the file > Pipeline permissions, remove open access and authorize only the pipelines that need it; add an approval check for signing material.'
    Requires    = @('SecureFiles')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($file in $Context.Collections.SecureFiles.Items) {
            $all = $file['_pipelinePermissions']?['allPipelines']
            if (-not ($all -and $all['authorized'] -eq $true)) { continue }
            New-AdoScopeFinding -Project $file['_project']?['name'] -Resource $file.name -ResourceId ([string]$file.id) `
                -Detail "Secure file '$($file.name)' can be downloaded by every pipeline in the project."
        }
    }
}
