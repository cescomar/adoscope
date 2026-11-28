# Changelog

All notable changes to adoscope. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

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
