# adoscope

[![ci](https://github.com/cescomar/adoscope/actions/workflows/ci.yml/badge.svg)](https://github.com/cescomar/adoscope/actions/workflows/ci.yml)

Read-only security and governance audit for **Azure DevOps Services** organizations.

adoscope reads the configuration of an organization through the REST API and reports
what is risky, wasteful or abandoned: credentials open to every pipeline, secrets
stored in plain text, production environments without approvals, branches without
review, outdated agents, unused paid licenses. Every finding explains **why it
matters** and **how to fix it**.

```
Critical (1)
  [SEC009] Credential stored as a plain-text pipeline variable: payments/deploy-settings
      Not marked secret: RegistryToken (value matches a credential format).
High (2)
  [SEC001] Service connection authorized for all pipelines: payments/azure-prod
  [PIP001] Production environment without approvals or checks: payments/production
Summary - Critical: 1, High: 2, Medium: 0, Low: 0, Info: 0 | suppressed: 0 | checks: 20/20 fully evaluated
```

## Why it is safe to run

- **GET only, by construction.** One HTTP client rejects every other method and sends
  credentials only to Azure DevOps hosts. No redirects are followed.
- **No secrets in output.** Variable values (variable groups and pipelines) are discarded
  at collection time and pipeline definitions are reduced to the fields checks use, so
  even a saved context holds no credentials; tokens are never printed and are redacted
  from errors.
- **Nothing leaves your machine.** No telemetry, no third-party calls.
- **Honest coverage.** If data cannot be read (for example 403), the affected checks
  are reported as *NotEvaluated* or *Partial*, never as clean, and the CI exit code says
  so. One unreadable resource never hides the others.

## What it checks

33 checks across security, identity, pipelines, agents, hygiene, cost and reliability, each
security check mapped to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
(shown in HTML, SARIF tags and the docs). Full list with rationale, remediation and
parameters: **[docs/checks.md](docs/checks.md)**.

| Area | Examples |
|---|---|
| Credentials | plain-text secrets in variable groups, pipeline and classic release variables; service connections, secret variable groups and secure files open to every pipeline; client secrets instead of workload identity federation |
| Pipelines | production environments and classic release stages without approvals; release creators approving their own deployments; required template missing; fork PR builds with secrets; weakened pipeline security settings; classic pipelines |
| Code | default branches without required reviewers; public projects |
| Agents | self-hosted pools shared across trust groups; outdated or long-offline agents |
| Hygiene and cost | pipelines and repositories unused for months; paid licenses of inactive users; pipelines that fail too often |
| Identity | too many collection or project administrators; inactive administrators; guest accounts with admin rights; organization not connected to Microsoft Entra ID; personal access tokens with full access, long lifetimes or valid in all organizations (metadata only, never token values) |

## Quick start

Requires PowerShell 7.2+ (Windows, Linux, macOS). No other dependencies.

```powershell
Import-Module ./adoscope.psd1

# Credentials, first match wins: -AccessToken, -Pat, $env:AZURE_DEVOPS_EXT_PAT,
# Azure CLI (az login) or Az PowerShell session, $env:SYSTEM_ACCESSTOKEN.
az login
Invoke-AdoScope -Organization fabrikam

# Reports for people and tools
Invoke-AdoScope -Organization fabrikam -HtmlPath ./adoscope.html -SarifPath ./adoscope.sarif -JsonPath ./adoscope.json

# Collect once, analyze offline (the file holds org data and user e-mails: keep it private)
Invoke-AdoScope -Organization fabrikam -SaveContextPath ./context.json
Invoke-AdoScope -ContextPath ./context.json -ConfigPath ./adoscope.config.psd1
```

Projects are collected 4 at a time by default (`-ThrottleLimit 1..16`; about 3x faster
than sequential on a 7-project organization). Expired Azure CLI / Az tokens are renewed
automatically during long audits.

The identity needs read access to what is audited. Organization-wide data (agent
pools, user licenses) and pipeline permissions usually require a Project Collection
Administrator or equivalent read rights; anything it cannot read shows up as a
coverage gap instead of a silent pass.

## Use in CI

`adoscope.ps1` wraps the module with exit codes for pipelines:

| Exit | Meaning |
|---|---|
| 0 | No unsuppressed finding at or above `-FailOn` (default `High`), full coverage |
| 1 | Findings at or above `-FailOn` |
| 2 | Some checks could not be evaluated: data unreadable, or a check not configured such as AGT001 without `trustGroups` (configure or disable it, or use `-AllowIncompleteCoverage`) |
| 3 | The audit failed (authentication, configuration, network) |

**Adopting the gate on an organization with existing findings.** Save today's report
once and use it as a baseline: the build fails only on findings that are *new*, while
the report shows how many known ones were resolved. A finding counts as resolved only
when the run could have seen it (check fully evaluated, project in scope, same
parameters); one that vanished because of a 403 or a changed threshold is reported as
*unverified*, never as fixed.

```powershell
./adoscope.ps1 -Organization fabrikam -JsonPath ./baseline.json -FailOn None   # once
./adoscope.ps1 -Organization fabrikam -BaselinePath ./baseline.json            # every run
```

**Ready-made weekly audit:** [templates/azure-pipelines.yml](templates/azure-pipelines.yml)
runs every Monday with a workload identity federation connection, applies your config and
baseline, and publishes JSON, SARIF and HTML reports as a pipeline artifact. Copy it into a
private repository next to `adoscope.config.psd1`.

Azure Pipelines, with a workload identity federation service connection whose service
principal is a user of the organization:

```yaml
steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: adoscope-reader
    scriptType: pscore
    scriptLocation: inlineScript
    inlineScript: >
      ./adoscope.ps1 -Organization fabrikam -ConfigPath ./adoscope.config.psd1
      -HtmlPath $(Build.ArtifactStagingDirectory)/adoscope.html
      -SarifPath $(Build.ArtifactStagingDirectory)/adoscope.sarif
- publish: $(Build.ArtifactStagingDirectory)
  artifact: adoscope
  condition: always()
```

GitHub Actions, with a PAT stored as a secret:

```yaml
- run: ./adoscope.ps1 -Organization fabrikam -SarifPath adoscope.sarif
  shell: pwsh
  env:
    AZURE_DEVOPS_EXT_PAT: ${{ secrets.ADO_READ_PAT }}
```

The SARIF file validates against the official SARIF 2.1.0 schema; findings carry
stable fingerprints so results do not duplicate across runs.

**Operating it safely.**

- *Pin what runs.* Use a released version, not `main`; the template pins one. Change the
  pin through a reviewed pull request.
- *Review what changes the gate.* `adoscope.config.psd1`, the baseline and suppressions
  decide what fails the build: keep them in the repository, change them only through
  reviewed pull requests (for example with a CODEOWNERS entry), and never regenerate the
  baseline automatically, or new findings get accepted silently.
- *Treat outputs as confidential.* Reports, saved contexts and logs contain user names
  and emails, resource names and configuration details (never secret values). Keep them
  in private repositories or artifacts with restricted access and a retention limit
  (Azure Pipelines artifact retention, GitHub Actions `retention-days`).
- *Use a dedicated audit identity*, preferably workload identity federation, rather than a
  person's account. When it cannot read something, the report lists the collection, the
  API it called and the checks affected, instead of reporting them clean.

## Configuration

Optional `adoscope.config.psd1` (PowerShell data file: comments allowed, never executed):

```powershell
@{
    Organization = 'fabrikam'
    Projects     = @('payments', 'web')        # default: all projects
    Checks       = @{
        Disabled   = @('HYG002')
        Parameters = @{
            HYG001 = @{ days = 60 }
            AGT001 = @{ trustGroups = @{ production = @('payments'); sandbox = @('playground') } }
        }
        Severity   = @{ PIP003 = 'Medium' }
    }
    Suppressions = @(
        # Fingerprint from a JSON/SARIF report. Reason and Expires are mandatory.
        @{ Check = 'SEC001'; Fingerprint = '<sha256>'; Reason = 'Accepted until WIF migration (CHG-1234)'; Expires = '2026-12-31' }
    )
}
```

Typos (unknown keys, checks or parameters) and invalid values (negative days, a project
in two trust groups, a version that is not a version) are errors, raised before any API
call. Expired suppressions stop
applying and are reported; suppressions that no longer match anything are reported
too, so exceptions do not pile up.

## Development

```powershell
Install-Module Pester -MinimumVersion 5.5 -MaximumVersion 5.99.99 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
./build.ps1                    # PSScriptAnalyzer (default rules) + Pester, same as CI
./tools/Update-CheckDoc.ps1    # regenerate docs/checks.md after changing a check
```

- Architecture, data model and every decision: [SPEC.md](SPEC.md).
- A check is one file, `src/Checks/<Category>/<ID>.ps1`, returning metadata and a
  `Test` script block that reads the collected context; it never calls the API.
- Tests run offline on synthetic fixtures (`tests/Fixtures`).
- Live testing: `lab/Initialize-AdoScopeLab.ps1 -Organization <org>` creates a
  disposable `adoscope-lab` project with resources the checks must and must not flag.
  It is the only script that writes to an organization; delete the project to clean up.
- `lab/Test-AdoScopeLab.ps1` (read-only) verifies that adoscope finds exactly the expected
  lab issues; the `lab` workflow runs it nightly to catch Azure DevOps API changes.

## Limitations

- Azure DevOps Services only (not Azure DevOps Server).
- Configuration audit, not a penetration test; it does not scan repository content
  for secrets.
- 30 of 33 checks have been seen reporting on a live organization; SEC004, SEC006 and
  IAM003 are covered by offline tests only.

## License

[MIT](LICENSE)
