"""Tests for the 8 Azure RBAC detection rules. Positive + negative per rule."""

from __future__ import annotations

from cloud_iam_auditor.base import Severity
from cloud_iam_auditor.rules.registry import all_azure_rules


def _rule(rule_id: str):
    return all_azure_rules()[rule_id]()


def test_azure001_classic_admin(load):
    statements = load("azure_classic_admin.json").statements
    findings = _rule("AZURE001").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert findings[0].provider.value == "azure"
    assert "Classic Administrator" in findings[0].evidence


def test_azure001_benign_skipped(load):
    statements = load("azure_benign.json").statements
    assert _rule("AZURE001").evaluate(statements) == []


def test_azure002_owner_subscription(load):
    statements = load("azure_owner_subscription.json").statements
    findings = _rule("AZURE002").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert "Owner" in findings[0].evidence


def test_azure002_owner_rg_skipped():
    statements = [{
        "roleDefinitionId": "/x/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe2c4fcb611",
        "role_name": "Owner",
        "principalId": "p1",
        "scope": "/subscriptions/aa/resourceGroups/rg1",
    }]
    assert _rule("AZURE002").evaluate(statements) == []


def test_azure003_uaa_subscription(load):
    statements = load("azure_uaa_subscription.json").statements
    findings = _rule("AZURE003").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL


def test_azure003_uaa_rg_skipped():
    statements = [{
        "roleDefinitionId": "/x/roleDefinitions/18d7d88d-d357-4073-9c1d-7f6c5f7f6e2a",
        "role_name": "User Access Administrator",
        "principalId": "p1",
        "scope": "/subscriptions/aa/resourceGroups/rg1",
    }]
    assert _rule("AZURE003").evaluate(statements) == []


def test_azure004_kvcontrib_sub(load):
    statements = load("azure_kvcontrib_sub.json").statements
    findings = _rule("AZURE004").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH
    assert "Key Vault Contributor" in findings[0].evidence


def test_azure004_kvcontrib_vault_scope_skipped():
    statements = [{
        "roleDefinitionId": "/x/roleDefinitions/f25e1a64-01d0-4a52-ba22-7a027bede7f8",
        "role_name": "Key Vault Contributor",
        "principalId": "p1",
        "scope": "/subscriptions/aa/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1",
    }]
    assert _rule("AZURE004").evaluate(statements) == []


def test_azure005_blob_sub(load):
    statements = load("azure_blob_sub.json").statements
    findings = _rule("AZURE005").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_azure005_blob_rg_scope_skipped():
    statements = [{
        "roleDefinitionId": "/x/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        "role_name": "Storage Blob Data Contributor",
        "principalId": "p1",
        "scope": "/subscriptions/aa/resourceGroups/rg1",
    }]
    assert _rule("AZURE005").evaluate(statements) == []


def test_azure006_aks_sub(load):
    statements = load("azure_aks_sub.json").statements
    findings = _rule("AZURE006").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_azure007_sql_sub(load):
    statements = load("azure_sql_sub.json").statements
    findings = _rule("AZURE007").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_azure008_owner_no_condition_skipped_when_conditioned(load):
    statements = load("azure_owner_with_condition.json").statements
    assert _rule("AZURE008").evaluate(statements) == []


def test_azure008_owner_no_condition_fires(load):
    statements = load("azure_owner_subscription.json").statements
    findings = _rule("AZURE008").evaluate(statements)
    assert findings and findings[0].severity == Severity.MEDIUM


def test_azure_registry_has_eight_rules():
    assert len(all_azure_rules()) == 8


def test_azure_rule_ids_unique():
    ids = list(all_azure_rules().keys())
    assert sorted(ids) == sorted(set(ids))


def test_azure_combined_reports_expected_rules(load):
    """azure_combined.json triggers the expected superset of findings."""
    statements = load("azure_combined.json").statements
    triggered = {
        finding.rule_id
        for rule in all_azure_rules().values()
        for finding in rule().evaluate(statements)
    }
    # AZURE005 should NOT fire - the only Storage Blob Data Contributor
    # in this fixture is at resource-group scope, not subscription.
    assert triggered == {"AZURE001", "AZURE002", "AZURE003", "AZURE004", "AZURE008"}
