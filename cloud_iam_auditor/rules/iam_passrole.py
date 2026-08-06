"""IAM004: iam:PassRole granted on a wildcard ('*') Resource."""

from __future__ import annotations

from ..base import Finding, Provider, Rule, Severity, Statement
from ..rules.registry import registry


def _is_wildcard(value) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


def _contains_passrole(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        v = value.lower()
        return v == "*" or v == "iam:passrole"
    if isinstance(value, list):
        return any(
            isinstance(v, str) and (v == "*" or v.lower() == "iam:passrole")
            for v in value
        )
    return False


@registry.register
class IamPassRoleRule(Rule):
    rule_id = "IAM004"
    title = "iam:PassRole on wildcard ('*') Resource enables privilege escalation"
    severity = Severity.HIGH
    provider = Provider.AWS
    description = (
        "An Allow statement grants iam:PassRole (or '*') against '*', letting the principal "
        "forward any role ARN to a service - a well-known path to privilege escalation (e.g. "
        "EC2 role chaining, CloudFormation elevation)."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if not _contains_passrole(stmt.get("Action")):
                continue
            if _is_wildcard(stmt.get("Resource")):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"Action includes iam:PassRole and Resource = {stmt.get('Resource')!r}"
                        ),
                        remediation=(
                            "Constrain Resource to a specific allow-list of role ARNs the principal "
                            "is explicitly permitted to pass, and add a Condition "
                            "iam:PassedToService to bound which services may receive the role."
                        ),
                        framework_refs=["NIST_AC_3", "MITRE_T1078_004"],
                    )
                )
        return findings
