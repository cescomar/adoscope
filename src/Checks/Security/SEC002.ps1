@{
    Id          = 'SEC002'
    Title       = 'Azure service connection uses a client secret'
    Category    = 'Security'
    Severity    = 'High'
    Rationale   = 'A client secret is a long-lived credential: it expires and breaks deployments, and if leaked it works from anywhere until revoked. Workload identity federation issues short-lived tokens and stores no secret.'
    Remediation = 'Convert the service connection to workload identity federation (Edit > Convert in the service connection page), or recreate it with that scheme, then delete the old client secret in Entra ID.'
    Requires    = @('ServiceConnections')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($endpoint in $Context.Collections.ServiceConnections.Items) {
            $scheme = $endpoint['authorization']?['scheme']
            if ($endpoint['type'] -ne 'azurerm' -or $scheme -ne 'ServicePrincipal') { continue }
            # authenticationType is absent on old connections; spnKey is the default.
            if ($endpoint['authorization']['parameters']?['authenticationType'] -eq 'spnCertificate') { continue }
            if (-not $seen.Add($endpoint.id)) { continue }   # shared across projects: report once
            New-AdoScopeFinding -Project $endpoint['_project']?['name'] -Resource $endpoint.name -ResourceId $endpoint.id `
                -Detail "Service connection '$($endpoint.name)' authenticates with a service principal client secret."
        }
    }
}
