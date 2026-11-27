BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
}

Describe 'Get-AdoScopeContext' {
    BeforeEach {
        Mock Get-AdoProject -ModuleName adoscope { @(@{ id = 'p1'; name = 'alpha' }, @{ id = 'p2'; name = 'beta' }) }
        Mock Get-AdoBuildDefinition -ModuleName adoscope { @{ id = 1; name = "def-$($Project.name)" } }
    }

    It 'collects only requested collections, restricted to -Project' {
        $context = InModuleScope adoscope {
            Get-AdoScopeContext -Organization 'o' -Auth ([pscustomobject]@{}) -Collection 'BuildDefinitions' -Project 'beta'
        }
        $context.Collections.Projects.Items.name | Should -Be 'beta'
        $context.Collections.BuildDefinitions.Status | Should -Be 'Ok'
        $context.Collections.BuildDefinitions.Items.name | Should -Be 'def-beta'
        $context.Collections.ContainsKey('ServiceConnections') | Should -BeFalse
    }

    It 'rejects unknown project names' {
        { InModuleScope adoscope { Get-AdoScopeContext -Organization 'o' -Auth ([pscustomobject]@{}) -Collection @() -Project 'gamma' } } |
            Should -Throw '*Unknown project*gamma*'
    }

    It 'marks a collection <Expected> when <Case>' -ForEach @(
        @{ Case = 'one project is denied'; Codes = @(403, 0); Expected = 'Partial' }
        @{ Case = 'every project is denied'; Codes = @(403, 401); Expected = 'Forbidden' }
        @{ Case = 'every project fails, not all denied'; Codes = @(403, 500); Expected = 'Failed' }
    ) {
        $script:codes = @{ alpha = $Codes[0]; beta = $Codes[1] }
        Mock Get-AdoServiceConnection -ModuleName adoscope {
            $code = $script:codes[$Project.name]
            if ($code) { throw [System.Net.Http.HttpRequestException]::new("HTTP $code", $null, [System.Net.HttpStatusCode]$code) }
            @{ id = 'e1'; name = 'ok' }
        }
        $context = InModuleScope adoscope {
            Get-AdoScopeContext -Organization 'o' -Auth ([pscustomobject]@{}) -Collection 'ServiceConnections' -WarningAction SilentlyContinue
        }
        $context.Collections.ServiceConnections.Status | Should -Be $Expected
        $context.Collections.ServiceConnections.Error | Should -Match 'alpha: HTTP'
    }
}
