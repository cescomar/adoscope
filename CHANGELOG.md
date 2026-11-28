# Changelog

All notable changes to adoscope. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **Baseline: "Resolved" now needs proof.** A baseline finding that is gone counts as
  resolved only if its check is fully evaluated, its project is in scope and its
  parameters are unchanged; otherwise it is counted as `Unverified` (report, console,
  HTML). Before, a 403 on service connections turned their findings into "resolved".
- **AGT001 without `trustGroups` is NotEvaluated** instead of a clean "Evaluated": it
  cannot find anything unconfigured. `adoscope.ps1` therefore exits 2 by default until
  `trustGroups` are set or AGT001 is disabled. New optional check metadata
  `RequiredParameters`.
- **Config parameter values are validated** before any API call (type from the default,
  positive numbers, plus check rules through optional `Validate` metadata: AGT001,
  AGT002, REL001). For example `HYG001.days = -30` was accepted before.
- Reports carry their provenance: `Scope` (`CollectedAt`, `Mode` Live/Offline, analyzed
  projects) and `SchemaVersion`; console and HTML show the collection date. Offline
  contexts older than 7 days print a warning. Saved contexts carry `SchemaVersion`; a
  context from a newer adoscope is rejected.

### Added

- **Personal access token inventory** (`PersonalAccessTokens`, Token Admin API, metadata only):
  **IAM006** (High) full-access token, **IAM007** (Medium) lifetime above `maxDays` (90),
  **IAM008** (Medium) token valid in all organizations. Verified live.
- **OWASP Top 10 CI/CD Security Risks** mapping: optional `Standards` check metadata
  (validated), shown in HTML, SARIF rule tags and `docs/checks.md`; every security check is mapped.

- **SEC013** (Medium): third-party marketplace extension with write, execute or manage
  scopes (`Extensions` collection; host `extmgmt.dev.azure.com` added to the allow-list).
  `vso.extension.*` scopes (the extension's own data) are ignored. Verified live by
  installing and removing a marketplace extension.
- **AGT003** verified live with a temporary agent (registered, stopped, removed).
- Classic build and release in the lab: PIP003, PIP004, PIP005 and SEC012 verified live and
  added to the nightly lab check (15 expected findings). SEC005 verified live once.
- `lab/lab.config.psd1`: the lab check skips HYG001/HYG002, which would start reporting the
  never-run lab resources after 90/180 days and fail the nightly job on their own.

### Fixed

- **AGT001** no longer reports empty agent pools (the built-in `Default` pool, shared by
  every project, has no agents). Found by running the checks on real data with lowered
  thresholds.

## [0.2.0] - 2026-11-28

### Added

- Classic release pipeline checks (`ReleaseDefinitions` collection, `vsrm` service):
  - **PIP004** (High): production stage of a classic release without manual approval or gates.
  - **PIP005** (Medium): release creator can approve their own production deployment.
  - **SEC012** (Critical): credential stored as a plain-text release or stage variable.
- Test that fails when a parameter of `Invoke-AdoScope` is not forwarded by `adoscope.ps1`.
- CI badge in the README; project and license links in the module manifest.

### Changed

- **AGT002** default minimum agent version raised from 4.0.0 to **5.0.0**: Microsoft only
  patches 5.x agents and publishes no new 4.x versions. Lower `minimumVersion` for hosts
  that cannot run .NET 10 yet.
- **SEC009/SEC011** no longer flag names that point to a credential instead of holding one
  (`TokenEndpoint`, `PasswordPolicyUrl`, `ClientSecretId`; configurable `nameExclusions`).
  A credential-shaped value is still always reported.
- IAM001 and IAM004 share one implementation (no behavior change).

### Fixed

- `docs/checks.md` staleness test failed on Windows checkouts (CRLF line endings).

## [0.1.0] - 2026-11-27

First public version: 26 checks (security, identity, pipelines, agents, hygiene, cost,
reliability), GET-only collection with host allow-list and credential redaction, honest
coverage (NotEvaluated / Partial), console, JSON, SARIF 2.1.0 and HTML reports, CI wrapper
with exit codes, configuration with expiring suppressions, baseline gate, parallel
collection, nightly lab verification.

[0.2.0]: https://github.com/cescomar/adoscope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cescomar/adoscope/releases/tag/v0.1.0
