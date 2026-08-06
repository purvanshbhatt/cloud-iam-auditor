# cloud-iam-auditor-pb

> A lightweight, offline CLI that audits an exported **AWS IAM JSON policy** for zero-trust violations and maps every finding to **NIST 800-53**, **NIST 800-207**, **CIS AWS Foundations**, and **MITRE ATT&CK Enterprise**.

[![PyPI version](https://img.shields.io/pypi/v/cloud-iam-auditor-pb.svg)](https://pypi.org/project/cloud-iam-auditor-pb/)
[![Python](https://img.shields.io/pypi/pyversions/cloud-iam-auditor-pb.svg)](https://pypi.org/project/cloud-iam-auditor-pb/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/purvanshbhatt/cloud-iam-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/purvanshbhatt/cloud-iam-auditor/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%3E85%25-brightgreen)](https://github.com/purvanshbhatt/cloud-iam-auditor)

`cloud-iam-auditor-pb` is a deterministic, no-credential-required security scanner. It does **not** call AWS - it parses an IAM policy document that you export (`aws iam get-policy-version` output, or `iam:SimulatePrincipalPolicy` JSON) and flags over-permissive patterns that violate least-privilege and zero-trust principles.

---

## Why this exists

Startups scale fast. Developers reach for `AdministratorAccess` or `Action: "*"` just to ship, creating security debt invisible until a breach. `cloud-iam-auditor-pb` lets an engineer drop a JSON file and answer:

> *Is this IAM role stuck in zero-trust debt? Which NIST/MITRE/CIS controls does it violate, and how do I fix it?*

in under one second, in their terminal or in CI.

---

## Install

```bash
pip install cloud-iam-auditor-pb
```

Requires Python >= 3.8. Works on Linux, macOS, and Windows.

---

## 10-second quickstart

```bash
iam-audit scan examples/sample_aws_policy.json
```

Sample output:

```
IAM Audit Report - examples/sample_aws_policy.json
┏━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
┃ # ┃ Rule   ┃ Severity  ┃ ...     ┃ Stmt ┃ Framework ┃ ...
┃ 1 ┃ IAM001 ┃ CRITICAL  ┃ Wildcard (*) Action detected ... ┃ ...
┃ 2 ┃ IAM003 ┃ CRITICAL  ┃ AWS-managed AdministratorAccess ... ┃ ...
┃ 3 ┃ IAM004 ┃ HIGH      ┃ iam:PassRole on wildcard ... ┃ ...
┃ ... 5 more findings ...
```

Use `--json` for a structured report consumable in CI:

```bash
iam-audit scan policy.json --json | jq '.summary'
```

---

## CLI reference

```
iam-audit --version
iam-audit scan PATH [--json] [--severity LEVEL] [--exit-code] [--no-color]
iam-audit rules
```

| Flag | Purpose |
|---|---|
| `--json` | Emit machine-readable JSON instead of a Rich table. |
| `--severity {low,medium,high,critical}` | Only report findings at or above the threshold. |
| `--exit-code` | Exit non-zero (1) when any finding remains - perfect for CI gates. |
| `--no-color` | Disable ANSI styling (accessibility / logs). |

---

## Detection rules (v0.1.0)

| ID | Rule | Severity | Map |
|---|---|---|---|
| IAM001 | `Action: "*"` on Allow | Critical | NIST AC-6 / CIS 1.16 / MITRE T1078.004 |
| IAM002 | `Resource: "*"` with broad Action set | High | NIST AC-6 / ZT 3.2.1 / CIS 1.16 |
| IAM003 | AWS-managed `AdministratorAccess` attached | Critical | NIST AC-6(5) / CIS 1.16 / MITRE T1078.004 |
| IAM004 | `iam:PassRole` against `"*"` | High | NIST AC-3 / MITRE T1078.004 |
| IAM005 | Sensitive action with no `Condition` block | Medium | NIST IA-2(1) / CIS 1.4 / MITRE T1098 |
| IAM006 | `NotAction` used with `Allow` | High | NIST AC-6 / CIS 1.16 |
| IAM007 | `NotResource` used with `Allow` | Medium | NIST AC-6 / CIS 1.16 |
| IAM008 | `sts:AssumeRole` against `"*"` (no trust condition) | High | NIST AC-6 / MITRE T1550.001 |
| IAM009 | `kms:Decrypt` against wildcard resource | High | NIST SC-12 / CIS 2.8 |
| IAM010 | `s3:PutObject` against `arn:aws:s3:::*/*` | Medium | NIST SC-28 / CIS 2.1.5 |

Run `iam-audit rules` to see the same table in your terminal.

---

## Framework mappings

Every finding ships with one or more framework references that the reporter renders inline. The full mapping table lives in [`cloud_iam_auditor/frameworks.py`](cloud_iam_auditor/frameworks.py) and covers:

- **NIST SP 800-53 Rev. 5** (e.g. AC-6, AC-6(5), AC-6(7), AC-3, SC-12, SC-28, IA-2, IA-2(1))
- **NIST SP 800-207** Zero Trust Architecture
- **CIS AWS Foundations Benchmark v3.0** (1.4, 1.16, 2.1.5, 2.8)
- **MITRE ATT&CK Enterprise** (T1078, T1078.004, T1098, T1556, T1550, T1550.001)

---

## CI/CD integration

Add this step to any GitHub Actions job after you check out the policy file:

```yaml
- run: pip install cloud-iam-auditor-pb
- run: iam-audit scan iam/release-role.json --json --exit-code --severity high
```

The job will fail (exit 1) if any High or Critical finding exists.

---

## Supported inputs

- Bare IAM policy document: `{"Version": "2012-10-17", "Statement": [...]}`
- Wrapped `aws iam get-policy-version` response: `{"PolicyDocument": {...}, "PolicyName": "..."}`
- Single statement **or** array of statements - loader normalizes both.

---

## What v0.1.0 does **not** do (by design)

- **No cloud credentials.** v0.1.0 is purely a static JSON audit; it never calls AWS.
- **GCP IAM** is on the v0.2.0 roadmap.
- **Live AWS mode** (boto3) is on the v0.2.0 roadmap.
- **SARIF** output is on the v0.2.0 roadmap.

This scoping keeps v0.1.0 auditable, dependency-light, and CI-friendly.

---

## Roadmap

See [`CHANGELOG.md`](CHANGELOG.md) for the planned v0.2.0 work.

---

## Development

```bash
git clone https://github.com/purvanshbhatt/cloud-iam-auditor
cd cloud-iam-auditor
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -e ".[dev]"
pytest -q
ruff check .
python -m build                 # produce wheel + sdist in dist/
```

---

## License

[MIT](LICENSE) - (c) 2026 Purvansh Bhatt.
