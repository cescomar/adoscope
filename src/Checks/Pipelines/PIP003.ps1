@{
    Id          = 'PIP003'
    Title       = 'Classic (non-YAML) build pipeline'
    Category    = 'Pipelines'
    Standards   = @('CICD-SEC-7')
    Severity    = 'Low'
    Rationale   = 'Classic pipelines are not versioned with the code, cannot be reviewed in pull requests, cannot extend required templates and receive no new features.'
    Remediation = 'Export the pipeline to YAML (pipeline editor > Export to YAML), commit it, create a YAML pipeline from it and delete the classic one. Then disable classic pipeline creation in Organization settings.'
    Requires    = @('BuildDefinitions')
    Test        = {
        param($Context, $Parameters)
        $null = $Parameters
        foreach ($definition in $Context.Collections.BuildDefinitions.Items) {
            if ($definition['process']?['type'] -ne 1) { continue }   # 1 = designer (classic), 2 = YAML
            New-AdoScopeFinding -Project $definition['project']?['name'] -Resource $definition.name -ResourceId ([string]$definition.id) `
                -Detail "Build pipeline '$($definition.name)' is defined in the classic designer."
        }
    }
}
