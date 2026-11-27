@{
    Id          = 'SEC007'
    Title       = 'Azure service connection uses a certificate'
    Category    = 'Security'
    Severity    = 'Medium'
    Rationale   = 'A certificate is stronger than a client secret but is still a long-lived credential stored in Azure DevOps that must be rotated. Workload identity federation stores no credential at all.'
    Remediation = 'Convert the service connection to workload identity federation, then remove the certificate from the app registration in Entra ID.'
    Requires    = @('ServiceConnections')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($endpoint in $Context.Collections.ServiceConnections.Items) {
            $scheme = $endpoint['authorization']?['scheme']
            if ($endpoint['type'] -ne 'azurerm' -or $scheme -ne 'ServicePrincipal') { continue }
            if ($endpoint['authorization']['parameters']?['authenticationType'] -ne 'spnCertificate') { continue }
            if (-not $seen.Add($endpoint.id)) { continue }
            New-AdoScopeFinding -Project $endpoint['_project']?['name'] -Resource $endpoint.name -ResourceId $endpoint.id `
                -Detail "Service connection '$($endpoint.name)' authenticates with a service principal certificate."
        }
    }
}
