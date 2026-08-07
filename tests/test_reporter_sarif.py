"""Tests for the SARIF 2.1.0 reporter."""

from __future__ import annotations

import json
from pathlib import Path

from cloud_iam_auditor.base import Finding, Provider, Severity
from cloud_iam_auditor.reporter_sarif import SARIF_LEVEL, render_sarif, render_sarif_to_file


def _sample_finding(rule_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Sample finding",
        statement_index=0,
        evidence="Wildcard('Resource = '*'')",
        remediation="Narrow the resource scope to specific ARNs.",
        framework_refs=["NIST_AC_6", "MITRE_T1078_004"],
        rule_description="description text",
        provider=Provider.AWS,
    )


def test_sarif_document_is_valid_json_and_has_top_level_keys():
    out = render_sarif([_sample_finding("IAM001")], source="aws:test.json")
    doc = json.loads(out)
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1


def test_sarif_run_emits_driver_with_rules_and_results():
    doc = json.loads(render_sarif([_sample_finding("IAM001")], source="aws:test.json"))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "cloud-iam-auditor-pb"
    assert run["tool"]["driver"]["informationUri"].startswith("https://github.com/")
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "IAM001"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "IAM001"


def test_sarif_level_mapping():
    assert SARIF_LEVEL[Severity.LOW] == "note"
    assert SARIF_LEVEL[Severity.MEDIUM] == "warning"
    assert SARIF_LEVEL[Severity.HIGH] == "error"
    assert SARIF_LEVEL[Severity.CRITICAL] == "error"


def test_sarif_deduplicates_rule_descriptors_across_multiple_findings():
    findings = [
        _sample_finding("IAM001", Severity.CRITICAL),
        _sample_finding("IAM001", Severity.HIGH),
        _sample_finding("IAM002", Severity.HIGH),
    ]
    doc = json.loads(render_sarif(findings, source="aws:test.json"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"IAM001", "IAM002"}
    assert len(doc["runs"][0]["results"]) == 3


def test_sarif_preserves_provider_and_framework_refs_on_result():
    doc = json.loads(render_sarif([_sample_finding("IAM003")], source="aws:json"))
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["provider"] == "aws"
    assert "NIST_AC_6" in result["properties"]["framework_refs"]


def test_render_sarif_to_file_writes_a_json_file(tmp_path: Path):
    out = tmp_path / "deep" / "out.sarif"
    render_sarif_to_file([_sample_finding("IAM001")], source="aws", out_path=str(out))
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
