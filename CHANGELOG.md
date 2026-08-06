# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Live AWS mode via boto3 (v0.3.0)
- SARIF output format for GitHub Code Scanning
- HTML report export
- Azure RBAC support

## [0.2.0] - 2026-08-06

### Added

- **Multi-cloud support.** GCP IAM role bindings (`gcloud projects get-iam-policy`
  output) are now auto-detected from the JSON shape and audited with a
  dedicated rule set, alongside the existing AWS JSON support.
- 5 new GCP rules (GCP001-GCP005): public privileged role, public-any-role,
  broad `serviceAccountUser`, primitive role assigned, broad
  `serviceAccountTokenCreator`.
- CIS GCP Foundations Benchmark mapping (1.3, 1.4, 1.5, 1.10).
- `Provider` enum + `Finding.provider` field surfaced in both Rich table
  (new `Cloud` column) and JSON `summary.by_provider` aggregate.
- Two separate rule registries (`aws_registry`, `gcp_registry`) so AWS rules
  never evaluate GCP bindings or vice versa.
- `iam-audit rules` now lists all 15 rules with a per-rule `Cloud` column.

### Changed

- README restructured with table of contents, provider-specific quickstart
  blocks, and rule tables split per cloud.
- `iam-audit scan` prints a one-line "Detected <PROVIDER>" status line.
- Summary panel reports per-provider finding counts.

### Backward compatibility

- v0.1.0 AWS rules, JSON output schema, CLI flags, and tests continue to work
  identically; only additive fields were added to finding output.

## [0.1.0] - 2026-08-05

### Added

- Initial release of `cloud-iam-auditor-pb`.
- Published `cloud-iam-auditor-pb` to PyPI so the CLI can be installed with `pip install cloud-iam-auditor-pb`.
- Typer-based CLI: `iam-audit scan`, `iam-audit rules`, `iam-audit --version`.
- AWS IAM JSON policy parser accepting both single-policy and bundled `PolicyDocument` shapes.
- Rule engine with 10 curated detection rules (IAM001-IAM010) covering wildcard actions/
  resources, `AdministratorAccess` attachment, `iam:PassRole` abuse, missing MFA/condition
  blocks, `NotAction`/`NotResource` over-permissiveness, `sts:AssumeRole` wildcard targeting,
  `kms:Decrypt` on any resource, and `s3:PutObject` against any bucket.
- Each finding mapped to NIST 800-53, NIST 800-207 (Zero Trust), CIS AWS Foundations Benchmarks,
  and MITRE ATT&CK Enterprise techniques.
- Dual output: color-coded Rich terminal table (default) and machine-readable JSON (`--json`).
- Severity filtering (`--severity`), CI exit-code gating (`--exit-code`), and `--no-color`
  accessibility flag.
- pytest suite with fixture-driven per-rule coverage and reporter snapshot tests.
- GitHub Actions CI matrix (Python 3.8-3.12, Ubuntu + Windows) running `ruff` and `pytest`.


