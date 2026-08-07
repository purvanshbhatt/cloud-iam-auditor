"""AZURE008: Elevated role assignment carries no Condition (ABAC) gate.

Several Azure elevated roles (Owner / User Access Administrator / Key Vault
  Contributor / Storage Blob Data Contributor) support Azure Role-Based
Access Control Conditions ("ABAC"). Without a Condition, the assignment is
standing privilege. Adding a Condition can limit access by source IP, time
window, resource tags, or principal. v0.3.0 flags elevated-role assignments
that ship without any Condition as a remediation-aware finding.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry

ELEVATED_TOKENS = (
    "owner",
    "user access administrator",
    "key vault contributor",
    "key vault administrator",
    "storage blob data contributor",
    "azure kubernetes service rbac cluster admin",
    "8e3af657-a8ff-443c-a75c-2fe2c4fcb611",  # Owner GUID
    "18d7d88d-d357-4073-9c1d-7f6c5f7f6e2a",  # UAA GUID
)


def _role_token(stmt: Statement) -> str:
    rid = stmt.get("roleDefinitionId") or stmt.get("role_name") or ""
    return rid.rsplit("/", 1)[-1].lower()


@azure_registry.register
class BrokenConditionOnElevatedRoleRule(Rule):
    rule_id = "AZURE008"
    title = "Elevated Azure role assigned without an ABAC Condition (standing privilege)"
    severity = Severity.MEDIUM
    provider = Provider.AZURE
    description = (
        "Elevated roles in Azure support Role-Based Access Control Conditions (ABAC) that "
        "narrow scope by source IP, time window, resource tag, or principal. Shipping an "
        "elevated assignment with no Condition means standing 24x7 privilege - the opposite "
        "of zero-trust."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt)
            is_elevated = (
                role in ELEVATED_TOKENS
                or any(token in role for token in ELEVATED_TOKENS)
            )
            if not is_elevated:
                continue
            condition = stmt.get("condition") or stmt.get("Condition")
            if not (isinstance(condition, str) and condition.strip()):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = {role!r}, principal = {stmt.get('principalId')!r}, "
                            f"condition = {condition!r}"
                        ),
                        remediation=(
                            "Add an Azure ABAC Condition restricting the assignment, e.g. by "
                            "source IP via @Request[].ipRanges, by resource tag via "
                            "ResourceGroup[tagName], or by time window. For human roles, also "
                            "activate via Privileged Identity Management for just-in-time."
                        ),
                        framework_refs=[
                            "NIST_AC_6_7",
                            "NIST_IA_2_1",
                            "MITRE_T1098",
                        ],
                    )
                )
        return findings
