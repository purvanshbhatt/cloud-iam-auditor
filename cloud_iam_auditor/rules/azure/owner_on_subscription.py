"""AZURE002: Owner role assigned at subscription scope.

`Owner` is the highest-privilege Azure RBAC role: full access to all resources
and the right to delegate access to others (effectively the Azure equivalent
of AWS AdministratorAccess). An Owner grant at the subscription scope means
the principal controls every resource in that subscription.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry


def _role_token(stmt: Statement) -> str:
    rid = stmt.get("roleDefinitionId") or stmt.get("role_name") or ""
    # roleDefinitionId URIs look like: .../roleDefinitions/8e3af657-a8ff-443c-a75c-2fe2c4fcb611
    return rid.rsplit("/", 1)[-1]


def _scope_token(stmt: Statement) -> str:
    scope = stmt.get("scope") or ""
    # scope strings look like: /subscriptions/<id> or /subscriptions/<id>/resourceGroups/<rg>
    return str(scope)


@azure_registry.register
class OwnerOnSubscriptionRule(Rule):
    rule_id = "AZURE002"
    title = "Owner role assigned at subscription scope"
    severity = Severity.CRITICAL
    provider = Provider.AZURE
    description = (
        "Owner is the highest-privilege Azure role (full access + delegation). "
        "Assigning it at the subscription scope means the principal controls every "
        "resource in the subscription and can grant further access."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt).lower()
            # Owner GUID is 8e3af657-...; match on either role_name or GUID postfix.
            is_owner = role == "owner" or role == "8e3af657-a8ff-443c-a75c-2fe2c4fcb611"
            if not is_owner:
                continue
            scope = _scope_token(stmt)
            if scope.startswith("/subscriptions/") and "/resourceGroups/" not in scope:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = 'Owner', scope = {scope!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Constrain the Owner grant to a single resource group or "
                            "downgrade to Contributor (no delegation) if full control is "
                            "genuinely required. Use Privileged Identity Management (PIM) "
                            "for just-in-time activation instead of a standing assignment."
                        ),
                        framework_refs=[
                            "CIS_AZURE_1_23",
                            "NIST_AC_6_5",
                            "MITRE_T1078_004",
                        ],
                    )
                )
        return findings
