"""IAM006: `NotAction` used with Effect: Allow (allow-all-except semantics)."""

from __future__ import annotations

from ..base import Finding, Provider, Rule, Severity, Statement
from ..rules.registry import registry


@registry.register
class NotActionAbuseRule(Rule):
    rule_id = "IAM006"
    title = "NotAction used on an Allow statement (allow-all-except semantics)"
    severity = Severity.HIGH
    provider = Provider.AWS
    description = (
        "An Allow statement uses NotAction, which becomes an implicit '*'. Anything not "
        "explicitly negated is permitted, frequently creating silent over-permissioning."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if "NotAction" in stmt:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"NotAction = {stmt.get('NotAction')!r}",
                        remediation=(
                            "If the intent is allow-list, switch to an explicit positive action "
                            "list via Action. NotAction on Allow should only be used in rare "
                            "deny-control patterns; document any unavoidable exception inline."
                        ),
                        framework_refs=["NIST_AC_6", "CIS_1_16"],
                    )
                )
        return findings
