"""IAM001: Wildcard ('*') Action on an Allow statement."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry


def _is_wildcard(value) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


@registry.register
class WildcardActionRule(Rule):
    rule_id = "IAM001"
    title = "Wildcard (*) Action detected on an Allow statement"
    severity = Severity.CRITICAL
    description = (
        "An Allow statement grants every AWS action via the '*' wildcard, violating "
        "the principle of least privilege and bypassing any per-service control."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action")
            if _is_wildcard(action):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"Action = {action!r}",
                        remediation=(
                            "Replace '*' with an explicit allow-list of actions the "
                            "principal actually needs. If still required temporarily, bind "
                            "it via a Condition (e.g. MFA, source IP, time window)."
                        ),
                        framework_refs=["NIST_AC_6", "ZT_3", "CIS_1_16", "MITRE_T1078_004"],
                    )
                )
        return findings
