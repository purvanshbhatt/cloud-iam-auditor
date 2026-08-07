"""AZURE001: Classic Administrator legacy role assigned.

`Classic Administrator` is a legacy Azure Service Manager role that bypasses
RBAC and grants near-account-wide permissions. It is deprecated, Microsoft
recommends against its use, and any assignment is a finding.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry


def _role_name(stmt: Statement) -> str:
    name = stmt.get("role_name") or stmt.get("roleDefinitionId") or ""
    return str(name)


@azure_registry.register
class ClassicAdministratorRule(Rule):
    rule_id = "AZURE001"
    title = "Legacy Classic Administrator role assigned"
    severity = Severity.CRITICAL
    provider = Provider.AZURE
    description = (
        "The deprecated Classic Administrator role bypasses Azure RBAC and grants "
        "near-account-wide permissions. Microsoft recommends migrating to built-in "
        "RBAC roles (Owner/Contributor/User Access Administrator) scoped narrowly."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            name = _role_name(stmt)
            if "Classic Administrator" in name or name.endswith("/ClassicAdministrator"):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = {name!r}, principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Remove the Classic Administrator assignment via "
                            "`az role assignment delete --ids <assignmentId>`. Replace "
                            "with a narrowly-scoped RBAC role bound to a single resource "
                            "or resource group."
                        ),
                        framework_refs=[
                            "CIS_AZURE_1_3",
                            "NIST_AC_6_5",
                            "MITRE_T1078_004",
                        ],
                    )
                )
        return findings
