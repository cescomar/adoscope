@{
    Id          = 'SEC013'
    Title       = 'Third-party extension with write or manage permissions'
    Category    = 'Security'
    Standards   = @('CICD-SEC-8')
    Severity    = 'Medium'
    Rationale   = 'A marketplace extension acts with the OAuth scopes it was granted at install time, for every user who loads it. With write, execute or manage scopes it can change code, queue pipelines or alter settings; a compromised or malicious publisher update reaches the whole organization.'
    Remediation = 'Review the extension in Organization settings > Extensions: uninstall it if unused, otherwise confirm the publisher and that the scopes are needed. Restrict who can install extensions to Project Collection Administrators, and add trusted publishers to trustedPublishers in the config.'
    # Built-in Microsoft extensions (flags 'builtIn' or 'trusted') are skipped; disabled extensions do not run.
    # vso.extension.* scopes only reach the extension's own data store (e.g. vso.extension.data_write), not code or settings.
    Parameters  = @{
        riskyScopes       = @('*_write', '*_manage', '*_execute', '*_full')
        ignoredScopes     = @('vso.extension*')
        trustedPublishers = @()
    }
    Requires    = @('Extensions')
    Test        = {
        param($Context, $Parameters)
        foreach ($extension in $Context.Collections.Extensions.Items) {
            if ([string]$extension['flags'] -match '\b(builtIn|trusted)\b') { continue }
            if ([string]$extension['installFlags'] -match '\bdisabled\b') { continue }
            if ($extension['publisherId'] -in $Parameters.trustedPublishers) { continue }
            $risky = @(@($extension['scopes']) | Where-Object {
                    $scope = [string]$_
                    @($Parameters.riskyScopes | Where-Object { $scope -like $_ }).Count -and -not @($Parameters.ignoredScopes | Where-Object { $scope -like $_ }).Count
                } | Sort-Object)
            if (-not $risky) { continue }
            $id = "$($extension['publisherId']).$($extension['extensionId'])"
            New-AdoScopeFinding -Resource ([string]($extension['extensionName'] ?? $id)) -ResourceId $id `
                -Detail "Extension '$id' by '$($extension['publisherName'])' holds scopes: $($risky -join ', ')."
        }
    }
}
