BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../adoscope.psd1') -Force
}

Describe 'Invoke-AdoScopeRequest' {
    BeforeAll {
        # Synthetic, never a real token.
        $script:auth = InModuleScope adoscope {
            [pscustomobject]@{ Scheme = 'Basic'; Secret = (ConvertTo-AdoScopeSecureString -Value 'synthetic-pat'); Source = 'test' }
        }
        $script:uri = [uri]'https://dev.azure.com/fabrikam-sample/_apis/projects?api-version=7.1'
        function script:New-Response([int]$Status, [string]$Body = '{}', [hashtable]$Headers = @{}) {
            $h = @{ 'Content-Type' = @('application/json; charset=utf-8') }
            foreach ($k in $Headers.Keys) { $h[$k] = @($Headers[$k]) }
            [pscustomobject]@{ StatusCode = $Status; Content = $Body; Headers = $h }
        }
    }

    It 'refuses <Method> without making a call' -ForEach @(@{ Method = 'POST' }, @{ Method = 'DELETE' }, @{ Method = 'PATCH' }) {
        Mock Invoke-WebRequest -ModuleName adoscope { throw 'must not be called' }
        { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth; M = $Method } {
                param($U, $A, $M) Invoke-AdoScopeRequest -Uri $U -Auth $A -Method $M } } | Should -Throw '*read-only*'
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 0
    }

    It 'refuses to send credentials to <Target>' -ForEach @(
        @{ Target = 'https://example.com/x' }
        @{ Target = 'http://dev.azure.com/org/_apis/projects' }
        @{ Target = 'https://dev.azure.com.attacker.example/x' }
        @{ Target = 'https://extmgmt.dev.azure.com.attacker.example/x' }
    ) {
        Mock Invoke-WebRequest -ModuleName adoscope { throw 'must not be called' }
        { InModuleScope adoscope -Parameters @{ U = $Target; A = $auth } {
                param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } | Should -Throw '*Refused to send credentials*'
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 0
    }

    It 'sends a PAT as Basic auth with an empty user name, no redirects' {
        Mock Invoke-WebRequest -ModuleName adoscope { New-Response 200 '{"value":[]}' }
        InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } | Out-Null
        $expected = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(':synthetic-pat'))
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 1 -ParameterFilter {
            $Headers.Authorization -eq $expected -and $MaximumRedirection -eq 0 -and $Method -eq 'Get'
        }
    }

    It 'retries on 429 honoring Retry-After, then succeeds' {
        $script:calls = 0
        Mock Start-Sleep -ModuleName adoscope {}
        Mock Invoke-WebRequest -ModuleName adoscope {
            $script:calls++
            if ($script:calls -lt 3) { New-Response 429 '' @{ 'Retry-After' = '7' } } else { New-Response 200 '{"count":1}' }
        }
        $r = InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A }
        $r.Content.count | Should -Be 1
        Should -Invoke Start-Sleep -ModuleName adoscope -Times 2 -Exactly -ParameterFilter { $Seconds -eq 7 }
    }

    It 'renews an expired Azure CLI token once and retries with it' {
        $cliAuth = InModuleScope adoscope { [pscustomobject]@{ Scheme = 'Bearer'; Secret = (ConvertTo-AdoScopeSecureString -Value 'old-token'); Source = 'Azure CLI' } }
        $script:newSecret = InModuleScope adoscope { ConvertTo-AdoScopeSecureString -Value 'new-token' }
        Mock Get-AdoScopeAzureToken -ModuleName adoscope { [pscustomobject]@{ Scheme = 'Bearer'; Secret = $script:newSecret; Source = 'Azure CLI' } }
        Mock Invoke-WebRequest -ModuleName adoscope {
            if ($Headers.Authorization -eq 'Bearer old-token') { New-Response 401 '{"message":"expired"}' } else { New-Response 200 '{"count":1}' }
        }
        $r = InModuleScope adoscope -Parameters @{ U = $uri; A = $cliAuth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A }
        # 200 is returned only for the new token: success proves the retry used it.
        $r.Content.count | Should -Be 1
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 2 -Exactly
        Should -Invoke Get-AdoScopeAzureToken -ModuleName adoscope -Times 1 -Exactly
        # The renewed token is kept for the following requests.
        (InModuleScope adoscope -Parameters @{ A = $cliAuth } { param($A) Get-AdoScopeAuthorizationHeader -Auth $A }) | Should -Be 'Bearer new-token'
    }

    It 'does not try to renew a PAT: the authentication failure stands' {
        Mock Get-AdoScopeAzureToken -ModuleName adoscope { throw 'must not be called' }
        Mock Invoke-WebRequest -ModuleName adoscope { New-Response 401 '{"message":"expired"}' }
        { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } |
            Should -Throw '*authentication failed*'
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 1 -Exactly
    }

    It 'pauses when a successful response announces throttling, and still returns the data' {
        Mock Start-Sleep -ModuleName adoscope {}
        Mock Invoke-WebRequest -ModuleName adoscope { New-Response 200 '{"count":2}' @{ 'Retry-After' = '3'; 'X-RateLimit-Remaining' = '0' } }
        $r = InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A }
        $r.Content.count | Should -Be 2
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 1 -Exactly
        Should -Invoke Start-Sleep -ModuleName adoscope -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
    }

    It 'gives up after 5 attempts with exponential backoff' {
        Mock Start-Sleep -ModuleName adoscope {}
        Mock Invoke-WebRequest -ModuleName adoscope { New-Response 503 '{"message":"busy"}' }
        { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } |
            Should -Throw '*HTTP 503*'
        Should -Invoke Invoke-WebRequest -ModuleName adoscope -Times 5 -Exactly
        Should -Invoke Start-Sleep -ModuleName adoscope -Times 1 -Exactly -ParameterFilter { $Seconds -eq 16 }
    }

    It 'maps <Case> to an authentication failure' -ForEach @(
        @{ Case = '203 sign-in page'; Status = 203; Type = 'text/html' }
        @{ Case = '302 redirect'; Status = 302; Type = 'text/html' }
        @{ Case = '200 HTML'; Status = 200; Type = 'text/html' }
        @{ Case = '401'; Status = 401; Type = 'application/json' }
    ) {
        $script:mockStatus = $Status
        $script:mockType = $Type
        Mock Invoke-WebRequest -ModuleName adoscope {
            # Real Invoke-WebRequest writes a non-terminating error when a redirect is blocked.
            if ($script:mockStatus -eq 302) { Write-Error 'The maximum redirection count has been exceeded.' -ErrorAction $PesterBoundParameters.ErrorAction }
            [pscustomobject]@{ StatusCode = $script:mockStatus; Content = '<html/>'; Headers = @{ 'Content-Type' = @($script:mockType) } }
        }
        $err = { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } |
            Should -Throw '*authentication failed*' -PassThru
        $err.Exception.StatusCode | Should -Be 'Unauthorized'
    }

    It 'fails with the network error when there is no response' {
        Mock Invoke-WebRequest -ModuleName adoscope { throw 'No such host is known.' }
        { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } |
            Should -Throw '*No such host is known*'
    }

    It 'exposes 403 as StatusCode Forbidden and redacts the message' {
        Mock Invoke-WebRequest -ModuleName adoscope { New-Response 403 ('{"message":"denied for Bearer ' + ('a' * 30) + '"}') }
        $err = { InModuleScope adoscope -Parameters @{ U = $uri; A = $auth } { param($U, $A) Invoke-AdoScopeRequest -Uri $U -Auth $A } } |
            Should -Throw -PassThru
        $err.Exception.StatusCode | Should -Be 'Forbidden'
        $err.Exception.Message | Should -Match '\[REDACTED\]'
        $err.Exception.Message | Should -Not -Match 'aaaaaaaaaa'
    }
}

Describe 'Invoke-AdoScopeListRequest' {
    It 'follows <Kind> continuation tokens and emits all items' -ForEach @(@{ Kind = 'header' }, @{ Kind = 'body' }) {
        $script:mockKind = $Kind
        Mock Invoke-AdoScopeRequest -ModuleName adoscope {
            if ($Uri.Query -notmatch 'continuationToken=') {
                $c = @{ value = @(@{ id = 1 }, @{ id = 2 }) }
                if ($script:mockKind -eq 'body') { $c.continuationToken = 'next 1' }
                [pscustomobject]@{ Content = $c; ContinuationToken = if ($script:mockKind -eq 'header') { 'next 1' } else { $null } }
            }
            else {
                $Uri.Query | Should -Match 'continuationToken=next%201'
                [pscustomobject]@{ Content = @{ value = @(@{ id = 3 }) }; ContinuationToken = $null }
            }
        }
        $items = InModuleScope adoscope { Invoke-AdoScopeListRequest -Uri 'https://dev.azure.com/o/_apis/x?api-version=7.1' -Auth ([pscustomobject]@{}) }
        $items.id | Should -Be 1, 2, 3
    }

    It 'stops on a repeated continuation token' {
        Mock Invoke-AdoScopeRequest -ModuleName adoscope { [pscustomobject]@{ Content = @{ value = @() }; ContinuationToken = 'same' } }
        { InModuleScope adoscope { Invoke-AdoScopeListRequest -Uri 'https://dev.azure.com/o/_apis/x' -Auth ([pscustomobject]@{}) } } |
            Should -Throw '*Paging loop*'
    }
}

Describe 'Resolve-AdoScopeAuth' {
    BeforeEach {
        $script:savedEnv = @{ PAT = $env:AZURE_DEVOPS_EXT_PAT; SYS = $env:SYSTEM_ACCESSTOKEN }
        $env:AZURE_DEVOPS_EXT_PAT = $null
        $env:SYSTEM_ACCESSTOKEN = $null
        Mock Get-AdoScopeAzureToken -ModuleName adoscope { $null }
    }
    AfterEach {
        $env:AZURE_DEVOPS_EXT_PAT = $savedEnv.PAT
        $env:SYSTEM_ACCESSTOKEN = $savedEnv.SYS
    }

    It 'prefers explicit parameters over the environment' {
        $env:AZURE_DEVOPS_EXT_PAT = 'env-pat'
        (InModuleScope adoscope { Resolve-AdoScopeAuth -AccessToken (ConvertTo-AdoScopeSecureString -Value 'tok') }).Source | Should -Be '-AccessToken'
        (InModuleScope adoscope { Resolve-AdoScopeAuth }).Source | Should -Be 'AZURE_DEVOPS_EXT_PAT'
    }

    It 'prefers an Azure session over SYSTEM_ACCESSTOKEN' {
        $env:SYSTEM_ACCESSTOKEN = 'sys'
        Mock Get-AdoScopeAzureToken -ModuleName adoscope { [pscustomobject]@{ Scheme = 'Bearer'; Secret = $null; Source = 'Azure CLI' } }
        (InModuleScope adoscope { Resolve-AdoScopeAuth }).Source | Should -Be 'Azure CLI'
    }

    It 'throws when no credential source is available' {
        { InModuleScope adoscope { Resolve-AdoScopeAuth } } | Should -Throw '*No Azure DevOps credentials*'
    }
}

Describe 'Protect-AdoScopeText' {
    It 'redacts <Case>' -ForEach @(
        @{ Case = 'current PAT'; Secret = ('A1b2' * 21) }
        @{ Case = 'legacy PAT'; Secret = ('abcd2345' * 6 + 'abcd') }
        @{ Case = 'JWT'; Secret = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl' }
        @{ Case = 'Basic header'; Secret = 'Basic OnN5bnRoZXRpYw==' }
        @{ Case = 'GitHub token'; Secret = 'ghp_' + ('a1B2' * 9) }
        @{ Case = 'AWS key id'; Secret = 'AKIA' + ('ABCD2345' * 2) }
        @{ Case = 'connection string password'; Secret = 'Password=Synthetic123!' }
    ) {
        $out = InModuleScope adoscope -Parameters @{ S = $Secret } { param($S) Protect-AdoScopeText "error near $S here" }
        $out | Should -Be 'error near [REDACTED] here'
    }

    It 'leaves GUIDs and ordinary text alone' {
        $text = 'project 00000000-0000-0000-0000-000000000001 not found'
        InModuleScope adoscope -Parameters @{ T = $text } { param($T) Protect-AdoScopeText $T } | Should -Be $text
    }
}

Describe 'Organization and URI helpers' {
    It 'normalizes <Value>' -ForEach @(
        @{ Value = 'fabrikam' }
        @{ Value = 'dev.azure.com/fabrikam' }
        @{ Value = 'https://dev.azure.com/fabrikam/' }
        @{ Value = 'https://fabrikam.visualstudio.com' }
    ) {
        InModuleScope adoscope -Parameters @{ V = $Value } { param($V) ConvertTo-AdoScopeOrganization $V } | Should -Be 'fabrikam'
    }

    It 'rejects <Value>' -ForEach @(@{ Value = 'https://example.com/fabrikam' }, @{ Value = 'fab/rikam/x' }, @{ Value = '-bad' }) {
        { InModuleScope adoscope -Parameters @{ V = $Value } { param($V) ConvertTo-AdoScopeOrganization $V } } | Should -Throw '*Invalid*'
    }

    It 'builds URIs with the central api-version and escaped query values' {
        $u = InModuleScope adoscope { Get-AdoScopeApiUri -Organization 'fabrikam' -Path '_apis/userentitlements' -Service vsaex -Query @{ '$filter' = "a b" } }
        $u.AbsoluteUri | Should -Be 'https://vsaex.dev.azure.com/fabrikam/_apis/userentitlements?api-version=7.1&$filter=a%20b'
    }
}
