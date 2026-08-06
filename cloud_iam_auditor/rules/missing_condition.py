"""IAM005: Sensitive actions granted without any Condition block (e.g. missing MFA)."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry

SENSITIVE_ACTIONS = {
    "s3:deletebucket",
    "kms:decrypt",
    "kms:listkeys",
    "iam:createaccesskey",
    "iam:deletemfakernel",
    "iam:deletevirtualmfadevice",
    "sts:assumerole",
    "states:startexecution",
    "secretsmanager:getsecretvalue",
    "lambda:invokefunction",
}


def _action_matches(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        v = value.lower()
        return v == "*" or v in SENSITIVE_ACTIONS or v.endswith(":*")
    if isinstance(value, list):
        return any(
            isinstance(v, str) and (v == "*" or v.lower() in SENSITIVE_ACTIONS or v.lower().endswith(":*"))
            for v in value
        )
    return False


@registry.register
class MissingConditionRule(Rule):
    rule_id = "IAM005"
    title = "Sensitive action granted with no Condition (no MFA / source / time gate)"
    severity = Severity.MEDIUM
    description = (
        "An Allow statement grants a sensitive action (e.g. iam:CreateAccessKey, "
        "secretsmanager:GetSecretValue) with an empty or missing Condition block, exposing "
        "the capability to any authenticated session of the principal."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if not _action_matches(stmt.get("Action")):
                continue
            condition = stmt.get("Condition")
            if isinstance(condition, dict) and condition:
                continue
            findings.append(
                self._finding(
                    statement_index=idx,
                    evidence=f"Action = {stmt.get('Action')!r}, Condition = {condition!r}",
                    remediation=(
                        "Add a Condition block requiring aws:MultiFactorAuthPresent=true for any "
                        "human role, or scope via sourceVpc / sourceIp / time bounds; for STS "
                        "assume-role chains, require a trust condition on the assumed role ARN."
                    ),
                    framework_refs=["NIST_IA_2_1", "NIST_AC_6_7", "CIS_1_4", "MITRE_T1098"],
                )
            )
        return findings
