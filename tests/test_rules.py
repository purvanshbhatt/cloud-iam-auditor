"""Tests for every detection rule. One positive and at least one negative case per rule."""

from __future__ import annotations

from cloud_iam_auditor.base import Severity
from cloud_iam_auditor.rules.registry import all_rules


def _rule(rule_id: str):
    return all_rules()[rule_id]()


def test_iam001_wildcard_action(load):
    statements = load("wildcard_action.json").statements
    findings = _rule("IAM001").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert "Action" in findings[0].evidence


def test_iam001_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM001").evaluate(statements) == []


def test_iam002_wildcard_resource_with_list(load):
    statements = load("wildcard_resource.json").statements
    findings = _rule("IAM002").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_iam002_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM002").evaluate(statements) == []


def test_iam003_admin_attach(load):
    statements = load("admin_attach.json").statements
    findings = _rule("IAM003").evaluate(statements)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert "AdministratorAccess" in findings[0].evidence


def test_iam003_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM003").evaluate(statements) == []


def test_iam004_passrole_wildcard(load):
    statements = load("passrole_wildcard.json").statements
    findings = _rule("IAM004").evaluate(statements)
    assert findings and findings[0].rule_id == "IAM004"


def test_iam004_scoped_resource_skipped(load):
    statements = [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::123456789012:role/qa-runner"}]
    assert _rule("IAM004").evaluate(statements) == []


def test_iam005_missing_condition(load):
    statements = load("missing_condition.json").statements
    findings = _rule("IAM005").evaluate(statements)
    assert findings and findings[0].rule_id == "IAM005"


def test_iam005_with_condition_skipped(load):
    statements = [{
        "Effect": "Allow",
        "Action": "iam:CreateAccessKey",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    }]
    assert _rule("IAM005").evaluate(statements) == []


def test_iam006_not_action(load):
    statements = load("not_action.json").statements
    findings = _rule("IAM006").evaluate(statements)
    assert findings and "NotAction" in findings[0].evidence


def test_iam006_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM006").evaluate(statements) == []


def test_iam007_not_resource(load):
    statements = load("not_resource.json").statements
    findings = _rule("IAM007").evaluate(statements)
    assert findings and "NotResource" in findings[0].evidence


def test_iam007_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM007").evaluate(statements) == []


def test_iam008_sts_wildcard(load):
    statements = load("sts_assume_role_wildcard.json").statements
    findings = _rule("IAM008").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_iam008_with_condition_skipped(load):
    statements = [{
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*",
        "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::111111111111:role/svc"}},
    }]
    assert _rule("IAM008").evaluate(statements) == []


def test_iam009_kms_decrypt_wildcard(load):
    statements = load("kms_decrypt_wildcard.json").statements
    findings = _rule("IAM009").evaluate(statements)
    assert findings and findings[0].severity == Severity.HIGH


def test_iam009_scoped_resource_skipped(load):
    statements = [{
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": "arn:aws:kms:us-east-1:111111111111:key/abc",
    }]
    assert _rule("IAM009").evaluate(statements) == []


def test_iam010_s3_put_object_wildcard(load):
    statements = load("s3_put_object_wildcard.json").statements
    findings = _rule("IAM010").evaluate(statements)
    assert findings and findings[0].rule_id == "IAM010"


def test_iam010_benign_skipped(load):
    statements = load("benign_policy.json").statements
    assert _rule("IAM010").evaluate(statements) == []


def test_registry_has_ten_rules():
    assert len(all_rules()) == 10


def test_every_rule_id_is_unique():
    ids = list(all_rules().keys())
    assert sorted(ids) == sorted(set(ids))
