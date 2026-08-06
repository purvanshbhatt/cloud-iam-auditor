"""IAM008: sts:AssumeRole granted on wildcard ('*') Resource."""

from __future__ import annotations

from ..base import Finding, Provider, Rule, Severity, Statement
from ..rules.registry import registry


def _is_wildcard(value) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


def _contains_assume_role(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        v = value.lower()
        return v == "*" or v == "sts:assumerole"
    if isinstance(value, list):
        return any(
            isinstance(v, str) and (v == "*" or v.lower() == "sts:assumerole")
            for v in value
        )
    return False


def _has_iam_condition(condition) -> bool:
    """Return True if a trust condition limits assumed role (e.g. aws:PrincipalArn)."""
    if not isinstance(condition, dict):
        return False
    flattened = []
    for operators in condition.values():
        if isinstance(operators, dict):
            flattened.extend(operators.keys())
    bounded = any(k.lower().startswith("aws:") for k in flattened)
    return bool(bounded)


@registry.register
class StsAssumeRoleWildcardRule(Rule):
    rule_id = "IAM008"
    title = "sts:AssumeRole granted with wildcard Resource - account-wide role pivot"
    severity = Severity.HIGH
    provider = Provider.AWS
    description = (
        "An Allow statement grants sts:AssumeRole (or '*') against the '*' resource, letting "
        "the caller assume any role that trusts this principal - a common intruder pivot off "
        "soles like a single compromised IAM user."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if not _contains_assume_role(stmt.get("Action")):
                continue
            if not _is_wildcard(stmt.get("Resource")):
                continue
            # Skip if a binding Condition (e.g. aws:PrincipalArn list) is present.
            if _has_iam_condition(stmt.get("Condition")):
                continue
            findings.append(
                self._finding(
                    statement_index=idx,
                    evidence=(
                        f"Action includes sts:AssumeRole, Resource = {stmt.get('Resource')!r}"
                    ),
                    remediation=(
                        "Limit Resource to specific role ARNs that should be assumable from "
                        "this principal. Where wildcard is unavoidable, enforce explicit trust "
                        "policies on the target roles coupled with Condition keys like "
                        "aws:PrincipalArn / aws:PrincipalAccount."
                    ),
                    framework_refs=["NIST_AC_6", "MITRE_T1550_001"],
                )
            )
        return findings
