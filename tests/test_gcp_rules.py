"""Tests for GCP detection rules. Positive and negative case per rule."""

from __future__ import annotations

from cloud_iam_auditor.base import Severity
from cloud_iam_auditor.rules.registry import all_gcp_rules


def _rule(rule_id: str):
    return all_gcp_rules()[rule_id]()


def test_gcp001_public_privileged(load):
    statements = load("gcp_public_privileged.json").statements
    findings = _rule("GCP001").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert findings[0].rule_id == "GCP001"
    assert findings[0].provider.value == "gcp"
    assert "allUsers" in findings[0].evidence


def test_gcp001_low_role_not_flagged_here(load):
    """GCP001 should NOT fire for a public-but-low-priv role (GCP002 picks it up)."""
    statements = load("gcp_public_low.json").statements
    assert _rule("GCP001").evaluate(statements) == []


def test_gcp001_benign_skipped(load):
    statements = load("gcp_benign.json").statements
    assert _rule("GCP001").evaluate(statements) == []


def test_gcp002_public_any_role(load):
    statements = load("gcp_public_low.json").statements
    findings = _rule("GCP002").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_gcp002_benign_skipped(load):
    statements = load("gcp_benign.json").statements
    assert _rule("GCP002").evaluate(statements) == []


def test_gcp002_privileged_role_not_double_flagged(load):
    """GCP002 should NOT fire when the role is privileged (GCP001 owns the finding)."""
    statements = load("gcp_public_privileged.json").statements
    assert _rule("GCP002").evaluate(statements) == []


def test_gcp003_broad_service_account_user(load):
    statements = load("gcp_broad_sa_user.json").statements
    findings = _rule("GCP003").evaluate(statements)
    assert findings and findings[0].severity == Severity.MEDIUM


def test_gcp003_small_principal_count_skipped():
    statements = [{
        "role": "roles/iam.serviceAccountUser",
        "members": ["user:a@x.io", "user:b@x.io"],
    }]
    assert _rule("GCP003").evaluate(statements) == []


def test_gcp003_service_account_members_skipped():
    """Self-binding by SAs does not count as broad impersonation."""
    statements = [{
        "role": "roles/iam.serviceAccountUser",
        "members": [
            "serviceAccount:a@proj.iam.gserviceaccount.com",
            "serviceAccount:b@proj.iam.gserviceaccount.com",
            "serviceAccount:c@proj.iam.gserviceaccount.com",
            "serviceAccount:d@proj.iam.gserviceaccount.com",
        ],
    }]
    assert _rule("GCP003").evaluate(statements) == []


def test_gcp004_primitive_role(load):
    statements = load("gcp_primitive_role.json").statements
    findings = _rule("GCP004").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH
    assert "roles/editor" in findings[0].evidence


def test_gcp004_predefined_role_skipped(load):
    statements = load("gcp_benign.json").statements
    assert _rule("GCP004").evaluate(statements) == []


def test_gcp005_broad_token_creator(load):
    statements = load("gcp_broad_token_creator.json").statements
    findings = _rule("GCP005").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH
    assert "serviceAccountTokenCreator" in findings[0].evidence


def test_gcp005_small_count_skipped():
    statements = [{
        "role": "roles/iam.serviceAccountTokenCreator",
        "members": ["user:a@x.io", "user:b@x.io"],
    }]
    assert _rule("GCP005").evaluate(statements) == []


def test_gcp_registry_has_five_rules():
    assert len(all_gcp_rules()) == 5


def test_gcp_rule_ids_unique():
    ids = list(all_gcp_rules().keys())
    assert sorted(ids) == sorted(set(ids))


def test_gcp_combined_fixture_reports_expected_rules(load):
    """sample_gcp_policy.json + gcp_combined.json should trigger the expected set."""
    statements = load("gcp_combined.json").statements
    triggered = {f.rule_id for r in all_gcp_rules().values() for f in r().evaluate(statements)}
    assert triggered == {"GCP001", "GCP005", "GCP004"}
