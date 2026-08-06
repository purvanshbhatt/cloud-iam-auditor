"""Tests for the Reporter (Rich table + JSON) and the Typer CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cloud_iam_auditor.base import Finding, Severity
from cloud_iam_auditor.main import app
from cloud_iam_auditor.reporter import Reporter

runner = CliRunner()


def test_render_json_roundtrips_summary_and_findings():
    findings = [
        Finding(
            rule_id="IAM001",
            severity=Severity.CRITICAL,
            title="t",
            statement_index=0,
            evidence="Action = '*'",
            remediation="narrow it",
            framework_refs=["NIST_AC_6"],
        )
    ]
    out = Reporter(color=False).render_json(findings, source="sample.json")
    payload = json.loads(out)
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["critical"] == 1
    assert payload["findings"][0]["rule_id"] == "IAM001"


def test_cli_scan_passes_on_benign_policy(fixtures_dir: Path):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "benign_policy.json"), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["total"] == 0


def test_cli_scan_json_reports_findings(fixtures_dir: Path):
    result = runner.invoke(app, ["scan", str(fixtures_dir / "wildcard_action.json"), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["critical"] >= 1
    rules = {f["rule_id"] for f in payload["findings"]}
    assert "IAM001" in rules


def test_cli_scan_exit_code_when_findings_present(fixtures_dir: Path):
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "wildcard_action.json"), "--json", "--exit-code"],
    )
    assert result.exit_code == 1


def test_cli_scan_severity_filter_suppresses_low(fixtures_dir: Path):
    result = runner.invoke(
        app,
        ["scan", str(fixtures_dir / "kms_decrypt_wildcard.json"), "--json", "--severity", "critical"],
    )
    payload = json.loads(result.output)
    # No critical findings in this fixture => filter should drop every entry.
    assert payload["summary"]["total"] == 0


def test_cli_scan_invalid_severity_exits_two():
    result = runner.invoke(app, ["scan", "ignored.json", "--severity", "bogus"])
    assert result.exit_code == 2


def test_cli_scan_missing_file_exits_two():
    result = runner.invoke(app, ["scan", "does-not-exist.json", "--json"])
    assert result.exit_code == 2


def test_cli_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "iam-audit" in result.output


def test_cli_rules_subcommand_lists_all_ten():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    for rid in ["IAM001", "IAM002", "IAM003", "IAM004", "IAM005",
                "IAM006", "IAM007", "IAM008", "IAM009", "IAM010"]:
        assert rid in result.output
