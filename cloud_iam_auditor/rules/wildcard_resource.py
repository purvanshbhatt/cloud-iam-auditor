"""IAM002: Wildcard ('*') Resource used alongside broad Action set on an Allow."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry


def _is_wildcard(value) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


@registry.register
class WildcardResourceRule(Rule):
    rule_id = "IAM002"
    title = "Wildcard ('*') Resource paired with broad Action set"
    severity = Severity.HIGH
    description = (
        "An Allow statement grants actions against the '*' resource, meaning the permission "
        "applies to every resource of the action's service across every account it touches."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            resource = stmt.get("Resource")
            action = stmt.get("Action")
            # Only fire on '*' resource when Action is itself wildcarded OR a list of >=3 actions.
            broad = False
            if _is_wildcard(action):
                broad = True
            elif isinstance(action, list) and len(action) >= 3:
                broad = True
            if _is_wildcard(resource) and broad:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"Resource = {resource!r}, Action = {action!r}",
                        remediation=(
                            "Scope Resource to specific ARNs the principal needs. Where a service "
                            "genuinely requires '*' (e.g. S3 listAllMyBuckets) split into a second "
                            "tightly-scoped statement and document the exception."
                        ),
                        framework_refs=["NIST_AC_6", "ZT_3_2_1", "CIS_1_16"],
                    )
                )
        return findings
