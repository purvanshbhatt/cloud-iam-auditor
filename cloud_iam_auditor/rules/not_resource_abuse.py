"""IAM007: `NotResource` used with Effect: Allow."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry


@registry.register
class NotResourceAbuseRule(Rule):
    rule_id = "IAM007"
    title = "NotResource used on an Allow statement (allow-all-except resources)"
    severity = Severity.MEDIUM
    description = (
        "An Allow statement uses NotResource, implicitly granting access to any resource not "
        "enumerated - hard to reason about and a frequent source of accidental cross-tenant "
        "access."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if "NotResource" in stmt:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"NotResource = {stmt.get('NotResource')!r}",
                        remediation=(
                            "Replace NotResource with a positive Resource allow-list. Use "
                            "NotResource only inside an explicit Deny statement."
                        ),
                        framework_refs=["NIST_AC_6", "CIS_1_16"],
                    )
                )
        return findings
