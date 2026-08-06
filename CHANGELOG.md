# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- GCP IAM binding + policy support (v0.2.0)
- Live AWS mode via boto3 (v0.2.0)
- SARIF output format for GitHub Code Scanning
- HTML report export

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


