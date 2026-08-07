"""AZURE003: User Access Administrator role at subscription scope.

`User Access Administrator` lets the holder manage role assignments (RBAC)
on the scope it's granted. Paired with subscription scope, it's effectively
'can make anyone Owner of anything in this subscription' - the most dangerous
delegation primitive in Azure.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry

UA_ADMIN_GUID = "18d7d88d-d357-4073-9c1d-7f6c5f7f6e2a"


def _role_token(stmt: Statement) -> str:
    rid = stmt.get("roleDefinitionId") or stmt.get("role_name") or ""
    return rid.rsplit("/", 1)[-1]


def _scope_token(stmt: Statement) -> str:
    return str(stmt.get("scope") or "")


@azure_registry.register
class UserAccessAdminOnSubscriptionRule(Rule):
    rule_id = "AZURE003"
    title = "User Access Administrator at subscription scope (RBAC delegation pivot)"
    severity = Severity.CRITICAL
    provider = Provider.AZURE
    description = (
        "User Access Administrator grants the right to manage role assignments on the "
        "scope it's held against. Binding it at the subscription scope lets the principal "
        "make any other principal an Owner of any resource in the subscription."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt).lower()
            is_uaa = (
                role == "user access administrator"
                or role == UA_ADMIN_GUID
            )
            if not is_uaa:
                continue
            scope = _scope_token(stmt)
            if scope.startswith("/subscriptions/") and "/resourceGroups/" not in scope:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = 'User Access Administrator', scope = {scope!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Constrain UA Admin to a single resource group at most, and "
                            "prefer just-in-time activation via PIM. Never bind it to a "
                            "user principal at subscription scope; if automation requires "
                            "it, use a managed identity and add a Condition restricting "
                            "the role grant actions."
                        ),
                        framework_refs=[
                            "CIS_AZURE_1_23",
                            "NIST_AC_6_5",
                            "MITRE_T1098_001",
                        ],
                    )
                )
        return findings
