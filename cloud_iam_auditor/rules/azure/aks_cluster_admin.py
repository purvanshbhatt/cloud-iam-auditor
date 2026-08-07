"""AZURE006: Azure Kubernetes Service RBAC Cluster Admin at subscription scope.

`Azure Kubernetes Service RBAC Cluster Admin` grants full cluster-admin
privileges on every AKS cluster in the scope. At subscription scope, the
holder gains code-execution capabilities on every workload in every AKS
cluster, equivalent to root on every container host.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry


def _role_token(stmt: Statement) -> str:
    rid = stmt.get("roleDefinitionId") or stmt.get("role_name") or ""
    return rid.rsplit("/", 1)[-1].lower()


def _scope_token(stmt: Statement) -> str:
    return str(stmt.get("scope") or "")


@azure_registry.register
class AksClusterAdminRule(Rule):
    rule_id = "AZURE006"
    title = "AKS RBAC Cluster Admin at subscription scope - workload root"
    severity = Severity.HIGH
    provider = Provider.AZURE
    description = (
        "Azure Kubernetes Service RBAC Cluster Admin grants cluster-admin on every AKS "
        "cluster in the scope. At subscription scope this is effectively root on every "
        "container workload - a credential-exfiltration path."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt)
            is_aks_admin = (
                "aks rbac cluster admin" in role
                or "41097d4e-8aad-4e9e-9de5-a5b3eed78c2d" in role
            )
            if not is_aks_admin:
                continue
            scope = _scope_token(stmt)
            if scope.startswith("/subscriptions/") and "/providers/Microsoft.ContainerService/managedClusters/" not in scope:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = 'AKS RBAC Cluster Admin', scope = {scope!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Scope the assignment to a specific AKS cluster resource, and "
                            "prefer per-namespace Kubernetes RBAC roles over cluster-wide "
                            "cluster-admin in multi-tenant deployments. Use Azure AD group "
                            "membership to gate access for human operators."
                        ),
                        framework_refs=[
                            "NIST_AC_6_5",
                            "MITRE_T1611",
                        ],
                    )
                )
        return findings
