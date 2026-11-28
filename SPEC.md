# adoscope — Build Specification for AI Coding Agents

You are helping build **adoscope**, a PowerShell module that audits an Azure DevOps
organization for security risks, governance issues, unused resources and drift
from standards. Read this whole file before writing code.

## 1. Goal and target

Given an Azure DevOps organization, collect its configuration through the REST API,
run a set of independent checks against it, and report findings with severity,
rationale and remediation.

**Target platform: Azure DevOps Services (cloud) only.** Azure DevOps Server is not
supported (different base URL/collections, auth, api-versions, licensing; no public
projects).

The tool must be useful to DevOps / platform engineers (hygiene, cost, standards)
and to security engineers (credentials, permissions, pipeline risks).

## 2. Non-negotiable constraints

1. **Read-only, GET-only.** Every HTTP call goes through `Invoke-AdoScopeRequest`, which
   rejects any method other than GET. No POST "query" endpoints are used either (check
   configurations are read with one GET per environment), so there is no allow-list.
   Adding a non-GET call requires asking first (§13).
2. **Host allow-list.** The client only sends credentials to: `dev.azure.com`,
   `vsaex.dev.azure.com`, `vssps.dev.azure.com`, `vsrm.dev.azure.com`, `extmgmt.dev.azure.com`,
   `*.visualstudio.com` (legacy org URLs returned in `_links`), and Entra ID
   (`login.microsoftonline.com`). Anything else is rejected, including
   continuation/next links.
3. **No secrets in code, logs or output.** Tokens come from parameters, environment
   variables or an existing Azure session. Never print a token, even partially.
   Redact anything that looks like a credential in error messages.
4. **No data leaves the machine.** No telemetry, no external calls except to the
   hosts above.
5. **PowerShell 7.2+**, cross-platform. No Windows-only APIs.
6. **No external dependencies** beyond `Pester` 5 and `PSScriptAnalyzer` (dev only).
   Ask before adding anything else.
7. **Checks never call the API directly.** They only read the pre-collected
   context object. This keeps checks fast, testable and offline.
8. **Never report "clean" on missing data.** A check whose required collection is
   missing, failed or forbidden is `NotEvaluated`, never "zero findings".

## 3. Architecture

```
Invoke-AdoScope
   ├── Resolve-AdoScopeAuth      → bearer token (Entra) or PAT header
   ├── Import-AdoScopeConfig     → loads adoscope.config.psd1, validates against the catalog
   ├── Get-AdoScopeContext       → collectors fetch data once, build context
   │      (or Import-AdoScopeContext → load a saved context JSON, offline)
   │      ├── Get-AdoProject
   │      ├── Get-AdoBuildDefinition  (includeLatestBuilds + includeAllProperties)
   │      ├── Get-AdoServiceConnection (+ pipeline permissions)
   │      ├── Get-AdoEnvironment (+ check configurations)
   │      ├── Get-AdoRepository (+ branch policies)
   │      ├── Get-AdoAgentPool (+ agents) / Get-AdoAgentQueue (per project)
   │      ├── Get-AdoBuildGeneralSetting (per project)
   │      └── Get-AdoUserEntitlement
   ├── Invoke-AdoScopeCheck      → runs loaded checks, records per-check status
   ├── suppressions applied inside Invoke-AdoScope (by Fingerprint)
   └── report writers            → Console | Json | Sarif | Html
```

Naming: approved verbs and **singular nouns** (PSScriptAnalyzer default rules).

`Invoke-AdoScope` never calls `exit`. CI exit codes come from the wrapper script
`adoscope.ps1` (phase 5), which calls the cmdlet and exits.

### Folder layout

```
src/
  Public/        Exported cmdlets only (file name = function name)
  Private/
    Api/         HTTP client, paging, retry, rate limiting
    Collectors/  One file per resource type
    Reports/     One writer per output format
    Core/        Context, config, check loader/runner, finding model
  Checks/<Category>/<ID>.ps1
tests/
  Unit/
  Fixtures/      Synthetic JSON contexts/API responses and test-only checks
docs/checks.md   Generated from check metadata
build.ps1        PSScriptAnalyzer + Pester; same locally and in CI
adoscope.psd1
adoscope.psm1
```

## 4. Azure DevOps API notes

- Base URL: `https://dev.azure.com/{organization}`; user entitlements live on
  `https://vsaex.dev.azure.com/{organization}`.
- Use `api-version=7.1` unless an endpoint requires a preview version; centralize
  versions in one place. Known previews: pipeline permissions and check
  configurations (`7.1-preview.1`), user entitlements (`7.1-preview.3`),
  build general settings.
- Entra ID tokens are requested for the Azure DevOps resource
  `499b84ac-1321-427f-aa17-267ca6975798`. Sources, in order: `-AccessToken`,
  `az account get-access-token`, `Get-AzAccessToken` if Az is already loaded
  (Az ≥ 14 returns a SecureString). Neither Az nor the CLI is a dependency.
- PAT auth uses Basic auth with an empty username. `SYSTEM_ACCESSTOKEN` is
  accepted but sees a fraction of the org: warn about reduced coverage.
  Order: `-AccessToken`, `-Pat`, `AZURE_DEVOPS_EXT_PAT`, Azure CLI / Az session,
  `SYSTEM_ACCESSTOKEN`.
- Entra tokens from Azure CLI / Az expire (about 1 hour). On an authentication failure the
  client asks the same source for a new token **once** and retries; a PAT is never renewed.
- **Observed:** an invalid PAT gets **HTTP 302 to an HTML sign-in page** (sometimes
  203), not 401. The client never follows redirects and maps 203/3xx/non-JSON 200
  to an authentication failure.
- Handle continuation tokens (`x-ms-continuationtoken` header or
  `continuationToken` in body) for every list endpoint.
- Rate limiting is TSTU-based: Azure DevOps often **delays** requests instead of
  returning 429. On 429/503: retry with `Retry-After` or exponential backoff (max 5
  attempts). On a **successful** response carrying `Retry-After`: pause that long before
  the next call (logged with `X-RateLimit-Remaining` in verbose output).
- A failing secondary call (permissions, checks) marks **only its item**:
  `Add-AdoScopeEnrichment` sets the key to `$null` and `_error`; the item is kept, its
  siblings are analyzed, and the collection becomes `Partial`. Checks must treat a
  `$null` enrichment with `_error` as unknown (PIP001/PIP002 skip it), never as "none".
- 401/403 on a collector → that collection is `Forbidden`, not empty.
- Projects are collected in parallel (`-ThrottleLimit`, default 4, 1 = sequential) with
  `ForEach-Object -Parallel`: one task per project runs all requested collectors; each
  runspace imports the module once and gets its own credential copy (SecureString is not
  thread-safe). Results are merged in project order, so output does not depend on timing.
  Measured on a 7-project org: 17.2 s sequential, 6.0 s with 4, 5.4 s with 8; findings
  and collections identical in every mode. Organization-wide collections stay sequential.
  Unit tests exercise the sequential path (Pester mocks do not reach other runspaces);
  the parallel path shares the same per-project function.
- Avoid N+1 where an aggregate exists:
  - `build/definitions?includeLatestBuilds=true&includeAllProperties=true` gives
    `process.type` (1 = classic, 2 = YAML) and latest build in one paged call.
    **Observed:** without `includeAllProperties` the list omits `process` and `triggers`.
  - `build/builds?maxBuildsPerDefinition=50` per project, grouped locally, for failure rates.
  - Check configurations: one `GET .../checks/configurations?resourceType=environment`
    per environment (the POST query endpoint would break the GET-only rule).
- **Observed on a live org (phase 6):**
  - **Variable groups return non-secret values in clear text**; a real PAT stored as a
    plain variable was found this way. The collector keeps only `isSecret` and
    `_valueLooksLikeCredential`, never values.
  - **Build definitions carry the same risk**: with `includeAllProperties` they include
    pipeline variables (plain-text values) and classic task inputs such as inline scripts.
    Reproduced in the lab: a synthetic credential reached the saved context. The collector
    now keeps an allow-list of fields (id, name, path, project, process.type, createdDate,
    queueStatus, repository.type, latestBuild dates/result, triggers type/forks) and
    summarizes variables with the shared `ConvertTo-AdoScopeVariableSummary`. A new check
    that needs another definition field must add it to the allow-list explicitly.
    SEC011 reports credentials in pipeline variables (variables written inside the YAML
    file are not read).
  - Check types: Approval `8c6f20a7-a545-4486-9777-f762fafe0d4d`, Required template
    `ExtendsCheck` `4020e66e-b0f3-47e1-bc88-48f3cc59b5f3` (created and read back in the lab).
  - `build/builds?maxBuildsPerDefinition=50&queryOrder=finishTimeDescending` works per
    project without a definition filter.
  - Microsoft-hosted pools (`isHosted`) list placeholder agents (offline, no
    `statusChangedOn`): agent checks skip them, and elastic (scale-set) pools.
  - Minimum reviewers policy type `fa4e907d-c16b-4a4c-9dfa-4906e5d171dd`; scope
    `repositoryId = null` means every repository **of the policy's project**.
- **Observed on a live org:**
  - `build/generalsettings` exists only per project (404 at org level) and returns
    **effective** values: org-level enforcement overrides project PATCHes.
  - Pipeline permissions: `allPipelines` is **absent** unless the resource is open to
    all pipelines; `authorizedBy` contains user name and email (saved contexts hold PII).
  - Service connection secrets (`serviceprincipalkey`, `password`) are never returned;
    `authorization.parameters.authenticationType` is (`spnKey` | `spnCertificate`).
  - Dates arrive as UTC `DateTime` after `ConvertFrom-Json`.
  - Organizations can disable classic pipeline creation; the API then refuses it.
- Useful endpoints (verify each against the official REST API docs before use):
  - `_apis/projects`
  - `{project}/_apis/build/definitions`, `{project}/_apis/build/builds`
  - `{project}/_apis/build/generalsettings`
  - `{project}/_apis/serviceendpoint/endpoints`
  - `{project}/_apis/pipelines/pipelinePermissions/{resourceType}/{id}`
    (`endpoint`, `variablegroup`, `securefile`, `queue`, `environment`, `repository`)
  - `{project}/_apis/distributedtask/environments`
  - `{project}/_apis/pipelines/checks/configurations`
  - `{project}/_apis/git/repositories`, `{project}/_apis/policy/configurations`
  - `_apis/distributedtask/pools`, `_apis/distributedtask/pools/{id}/agents`
  - `{project}/_apis/distributedtask/queues`
  - `_apis/userentitlements` (on vsaex, `7.1-preview.3`; items in `members`,
    Basic license reported as `accountLicenseType = express` — observed)

If an endpoint behaves differently from these notes, trust the official docs,
update this file, and tell me.

## 5. Data model

### Context

Hashtables (not PSCustomObjects), identical for live and saved contexts. Under
`Set-StrictMode -Version Latest`, **dot access to a missing key throws**: read optional
fields with index syntax, `$item['key']`, `$item['a']?['b']`. Never use `?[`/`?.`
directly on a variable (`$x?['k']` parses as variable `x?`); use `${x}?['k']`.
Keys starting with `_` are added by collectors (`_project`, `_pipelinePermissions`,
`_checks`, `_error`).
`CollectedAt` is required; time-based checks measure from it, not from now.

```powershell
@{
    Organization = 'org'
    CollectedAt  = '2026-01-01T00:00:00Z'
    Collections  = @{
        Projects = @{ Status = 'Ok'; Items = @( @{ id = '...'; name = '...' } ); Error = $null }
    }
}
```

`Status`: `Ok | Partial | Failed | Forbidden`. An absent collection was not
collected. The context can be saved to / loaded from JSON (`-ContextPath`);
saved contexts contain real org data and are git-ignored.

### Finding

```powershell
[PSCustomObject]@{
    CheckId     = 'SEC001'
    Title       = '...'
    Category    = 'Security'
    Severity    = 'High'        # Critical | High | Medium | Low | Info
    Project     = 'project-name' # $null for org-level findings
    Resource    = 'resource-name'
    ResourceId  = 'guid-or-id'
    Detail      = 'Human-readable specifics'
    Rationale   = 'Why this matters'
    Remediation = 'What to do'
    Fingerprint = 'sha256(lower(CheckId|Project|ResourceId))'
    Suppressed  = $false
    InBaseline  = $false   # same Fingerprint present in the -BaselinePath report
    SuppressionReason = $null
}
```

Checks create findings with `New-AdoScopeFinding -Resource -ResourceId -Detail [-Project]`;
the runner fills check metadata and `Fingerprint`. The Fingerprint is the key for
suppressions and SARIF `partialFingerprints`.

### Check status

One per check in every report: `Evaluated | Partial | NotEvaluated | Error`, with
a message. `Error` = the check threw or emitted something that is not a finding;
other checks continue.

### Check file

Each check is a hashtable returned by its file; file name = `Id`:

```powershell
@{
    Id          = 'HYG001'
    Title       = 'Pipeline not run recently'
    Category    = 'Hygiene'
    Severity    = 'Low'
    Rationale   = '...'
    Remediation = '...'
    Parameters  = @{ days = 90 }   # defaults, overridable via config
    Standards   = @('CICD-SEC-1')  # optional: OWASP Top 10 CI/CD ids, validated at load
    Requires    = @('BuildDefinitions')   # context collections needed
    Test = {
        param($Context, $Parameters)
        # emit zero or more findings via New-AdoScopeFinding
    }
}
```

Collectors only run if at least one enabled check `Requires` their collection.
Invalid or duplicate checks are terminating errors at load time.

## 6. Check catalog

**Source of truth: the check files and the generated [docs/checks.md](docs/checks.md)**
(rationale, remediation, data, parameters). Design decisions not visible there:

- SEC001 covers service connections only. Variable groups and secure files have their
  own checks (SEC008, SEC010) so a 403 on one resource type does not make the others
  NotEvaluated. Agent queues, repositories and environments are open to all pipelines
  by default and were left out as noise; production environments are covered by PIP001/PIP002.
- SEC008 flags an open variable group only when it holds secrets (secret, Key Vault or
  credential-shaped value); an open group of plain settings is not a risk.
- SEC009 (Critical) was added after the live probe found a real plain-text PAT.
- SEC002/SEC007 split: one severity per rule.
- SEC003 does not accept self-approval (`creatorVoteCounts`) by default.
- SEC006 honours project/org fork protection (`forkProtectionEnabled`,
  `buildsEnabledForForks`, `enforceNoAccessToSecretsFromForks`, `enforceJobAuthScopeForForks`).
- PIP002 detects the Required template check instead of parsing YAML `extends:`.
- AGT001 needs `trustGroups` in the config; without it, it reports nothing. Empty pools
  (`pool.size = 0`) are skipped: the built-in `Default` pool is shared by every project but
  usually has no agents (false positive found live).
- **Live verification by lowered thresholds** (no change to the organization): with a
  temporary config (`days = 0`, `maxMembers = 0`, `maxFailureRate = 0`, trust groups), AGT001,
  HYG002, CST001, REL001, IAM001, IAM002 and IAM004 fired on real data with correct details.
  This proves they read the real API shapes; the thresholds themselves are covered by
  fixtures.
- **Live verification with temporary organization changes** (authorized by the owner; state
  snapshotted before and compared identical after): SEC013 (installed `cschleiden.prtemplates`,
  reported with `vso.code_write`, uninstalled); AGT003 (agent 5.282.0 registered in a dedicated
  pool scoped to the lab, started, stopped, reported offline, removed). SEC004 could not be
  exercised: the organization policy forbids public projects and has no public API.
  Organization pipeline settings have no public API either ("use the UI", Microsoft Learn): the
  owner disabled classic creation and job scope enforcement in the UI, the lab gained a classic
  build (`lab-classic`) and a classic release (`lab-release`: Production with automatic approval,
  prod-eu where the creator may approve, a plain-text credential), PIP003, PIP004, PIP005,
  SEC012 and SEC005 all reported live, then the owner re-enabled the settings and the snapshot
  compared identical. Existing classic definitions survive the re-enabled ban, so PIP003,
  PIP004, PIP005 and SEC012 are now in the nightly lab check; SEC005 stays a one-off test.
- Time-based checks measure from `CollectedAt`; text in details is culture-independent.

Identity checks (IAM001–IAM005) read the `AdminGroups` collection: Project Collection
Administrators and every project's Project Administrators, from the Graph API on
`vssps.dev.azure.com`, with nested groups expanded breadth-first (each group once, so
cycles terminate). **Observed:** Graph lists built-in service identities as users
(`origin = vsts`, domains `Build` / `AgentPool`; 137 of 138 "users" in a 7-project org);
they are dropped, otherwise every organization would show a hundred administrators.
Entitlement `user.descriptor` equals the Graph descriptor (verified), which joins "is an
administrator" with "last access" for IAM002. IAM005 relies on `origin = msa` (personal
Microsoft account), which only exists in organizations not backed by Entra ID.

Classic release checks (PIP004, PIP005, SEC012) read `ReleaseDefinitions` from
`vsrm.dev.azure.com`: the list endpoint, then one GET per definition (the list omits stage
approvals and variables). Kept per stage: approvals (`isAutomated` only, no approver
identities), `releaseCreatorCanBeApprover`, gate count, variables without values.
**Verified live** (see the lab notes above): the item shape of the official schema
(Definitions - Get, 7.1) matched a real classic release. PIP004/PIP005 skip
definitions that could not be read (unknown, not unprotected).

SEC013 reads `Extensions` from `extmgmt.dev.azure.com` (installed extensions, added to the
host allow-list with the owner's approval). **Observed:** built-in Microsoft extensions carry
`flags = 'builtIn, trusted'` and no scopes; the test organization has only those (30). The
check also ran live with a third-party extension installed (see above). `vso.extension.*`
scopes (e.g. `vso.extension.data_write`, seen on marketplace extensions) only reach the
extension's own data store and are ignored.

PAT checks (IAM006 full access, IAM007 lifetime above `maxDays`, IAM008 valid in all
organizations) read `PersonalAccessTokens`: the Token Admin API on `vssps`, one call per
licensed user, metadata only (name, scope, validity, target organizations). **Observed:**
the API returns `token`/`alternateToken` empty and full-access tokens as `scope = app_token`;
the collector keeps an allow-list regardless. `allOrganizations` (no target accounts) is
inferred from the schema; the test tokens were single-organization. Needs Project Collection
Administrator; a user whose tokens cannot be read makes the collection Partial.

Standards: every Security, Identity, Pipelines and Agents check carries `Standards` with
OWASP Top 10 CI/CD Security Risks ids (CICD-SEC-1..10), mapped from the official risk
descriptions; a test enforces it. Hygiene, cost and reliability checks map to none. CIS was
not used: no official CIS benchmark for Azure DevOps was found to cite.

Not implemented: variable groups not linked to Key Vault; fine-grained permissions such as
who can edit pipelines (security namespace ACL bits; high risk of wrong results).

## 7. Configuration

File: `adoscope.config.psd1`, a PowerShell data file read with `Import-PowerShellDataFile`
(no code execution, comments allowed, no dependency). YAML was dropped to avoid the
`powershell-yaml` dependency.

```powershell
@{
    Organization = 'fabrikam'                 # used when -Organization is not given
    Projects     = @('web', 'api')            # used when -Project is not given
    Checks       = @{
        Disabled   = @('HYG001')              # reported with status Disabled
        Parameters = @{ HYG001 = @{ days = 60 } }   # names must exist in the check's Parameters
        Severity   = @{ PIP003 = 'Medium' }
    }
    Suppressions = @(
        # Fingerprint (from a report) or ResourceId (+ optional Project); Reason and Expires required.
        @{ Check = 'SEC001'; Fingerprint = '<sha256>'; Reason = '...'; Expires = '2026-12-31' }
    )
}
```

- Unknown keys, check IDs and parameter names are errors: a typo must not silently
  fall back to defaults. Check-specific standards (production environment patterns,
  agent trust groups) are check `Parameters`, not top-level keys.
- Suppressions are valid through their `Expires` day. Each one is reported as `Active`,
  `Expired` (ignored; the finding is back) or `Unmatched` (nothing to suppress: fixed or
  wrong). These are configuration issues, shown in the report's `Suppressions` section,
  not findings. Suppressed findings stay in the report with `Suppressed = $true`.
- CLI parameters override config values.

## 8. Outputs

- **Console**: grouped by severity, colored, coverage gaps, stale suppressions,
  summary with suppressed count. Suppressed findings are not listed.
- **Json**: tool, version, timestamp, organization, collections, check statuses,
  suppressions, findings (suppressed ones flagged).
- **Sarif**: valid SARIF 2.1.0; one rule per check, one result per finding,
  `partialFingerprints` from Fingerprint, `logicalLocations` plus a synthetic
  `ado://{project}/{resourceType}/{id}` artifact URI (code scanning requires a location).
- **Html**: single self-contained file (CSP `default-src 'none'`, no external
  resources), every value HTML-encoded (resource names are attacker-controlled),
  findings sorted by severity, filters by category and severity, suppressed hidden
  by default.
- Invoke-AdoScope: console unless `-Quiet`; `-JsonPath`, `-SarifPath`, `-HtmlPath`
  in any combination; `-PassThru` returns the report (adds `Rules`: effective
  metadata of enabled checks).
- `-BaselinePath <previous JSON report>`: findings with a fingerprint already in it get
  `InBaseline = $true`; the report gains `Baseline { New; Existing; Resolved }`, the
  console marks known findings and counts new/resolved, SARIF sets `baselineState`
  (`new`/`unchanged`). A baseline of another organization is rejected.
- `adoscope.ps1` (CI wrapper, the only place that calls `exit`): `-FailOn
  <Severity|None>` (default High). Exit 0 ok; 1 unsuppressed, **not-in-baseline** findings
  at or above FailOn; 2 incomplete coverage (Partial/NotEvaluated/Error) unless
  `-AllowIncompleteCoverage`; 3 terminating error (message redacted of credentials).
- CI workflow: actions pinned to commit SHA, tools installed at exact versions,
  Dependabot proposes updates.

## 9. Coding conventions

- Approved verbs, singular nouns; `[CmdletBinding()]` on every function.
- Comment-based help on every public function, with examples.
- `Set-StrictMode -Version Latest` in the module.
- Errors: throw terminating errors for auth/config/catalog problems; for a single
  failed collector or check, write a warning, continue, and report it in the output.
- Pass `PSScriptAnalyzer` with default rules, no suppressions without a justification.
- Keep functions small: no more than ~60 lines of code, not counting comment-based help
  and attributes (the help of public functions is required and may be long).
- `./build.ps1` fails below 85% code coverage (Pester, `src` and `adoscope.psm1`).

## 10. Testing

- Pester 5 (pinned < 6). `./build.ps1` runs analyzer + tests.
- Every check has tests for: compliant resource → no finding;
  non-compliant → finding; missing optional data → no crash.
- Tests run offline using fixtures in `tests/Fixtures/`. Fixtures must be
  synthetic or fully sanitized: no real org names, IDs, emails or URLs.
- API client tests mock `Invoke-WebRequest`/`Invoke-RestMethod` and cover paging,
  429 retry, the read-only guard and the host allow-list.

## 11. Work plan

Phases 1–4 were delivered with a stop after each; phases 5–7 were completed in one
autonomous run at the owner's request.

1. **Skeleton** ✅: layout, manifest, finding model + fingerprint, context model,
   check loader/runner with coverage status, console + JSON output, Pester, CI.
2. **API layer** ✅: auth (Entra via token/CLI/Az session, PAT), HTTP client with
   read-only guard and host allow-list, paging, retry/rate limit, redaction.
   Fully unit-tested with mocks.
3. **First collectors and checks** ✅: Projects, BuildDefinitions, ServiceConnections
   (+ permissions), BuildGeneralSettings; checks SEC001 (endpoints), SEC002, SEC007,
   SEC005, HYG001, PIP003; `-Organization`, `-Project`, `-SaveContextPath`.
4. **Config and suppressions** ✅: `adoscope.config.psd1`, parameters, severity
   overrides, disabled checks, suppressions with expiry.
5. **Outputs** ✅: SARIF (validated against the official 2.1.0 schema), HTML, JSON,
   wrapper with `-FailOn` and exit codes.
6. **Remaining checks** ✅: 20 checks, 14 collections, lab extended, live audit 20/20
   fully evaluated. Later: identity checks IAM001–IAM005 (`AdminGroups`), 25 checks.
7. **Docs** ✅: `tools/Update-CheckDoc.ps1` generates `docs/checks.md`; a test fails
   when it is stale.

## 11b. Live lab

`lab/Initialize-AdoScopeLab.ps1 -Organization <org>` creates a disposable project
`adoscope-lab` with known-good and known-bad resources (synthetic IDs and secrets,
Manual-mode service connections that never contact Azure). It is the only code in the
repository that writes to an organization; it is not part of the module. Idempotent,
supports `-WhatIf`; delete the project to remove everything. Extend it whenever a new
check needs live data.

`lab/Test-AdoScopeLab.ps1 -Organization <org>` (read-only) runs adoscope on the lab project
and compares its findings with `lab/expected-findings.json`: exit 1 if any expected
finding is missing or any other appears. `.github/workflows/lab.yml` runs it nightly with
a read-only PAT (`ADO_LAB_READ_PAT` secret, `ADO_LAB_ORGANIZATION` variable) to catch
Azure DevOps API changes; it publishes no report artifact (org-wide data on a public repo).
When a check or the lab changes, update the expected list in the same commit.

## 12. Definition of done (per change)

- `./build.ps1` passes (tests + clean PSScriptAnalyzer).
- New checks are documented via their metadata and have fixtures.
- No secrets, real identifiers, non-GET calls or non-allow-listed hosts introduced.
- README / this file updated if behavior or structure changed.

## 13. When unsure

Ask instead of guessing on: new dependencies, changes to the finding model,
any endpoint that is not GET, and anything that would store or transmit data.
