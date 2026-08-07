"""AZURE007: SQL Server Manager / SQL DB Contributor at subscription scope.

`SQL Server Contributor` and `SQL DB Contributor` grant control over the
configuration of Azure SQL resources - including the ability to add a new
(notably Microsoft Entra ID) admin user, reset passwords, or read connection
strings used to extract the data plane. At subscription scope the holder can
pivot to data-plane access on every SQL server.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import azure_registry

SQL_ROLE_TOKENS = (
    "sql server contributor",
    "sql db contributor",
    "sql managed instance contributor",
)
SQL_ROLE_GUIDS = (
    "7d2d4234-2e8d-4f7d-b19c-2e8d4f7d6a8d",
)


def _role_token(stmt: Statement) -> str:
    rid = stmt.get("roleDefinitionId") or stmt.get("role_name") or ""
    return rid.rsplit("/", 1)[-1].lower()


def _scope_token(stmt: Statement) -> str:
    return str(stmt.get("scope") or "")


@azure_registry.register
class SqlServerAdminRule(Rule):
    rule_id = "AZURE007"
    title = "SQL Server/DB Contributor at subscription scope - data-plane pivot"
    severity = Severity.HIGH
    provider = Provider.AZURE
    description = (
        "SQL Server Contributor / SQL DB Contributor grant configuration control over "
        "Azure SQL resources - enough to add an Entra ID admin and read out data, or to "
        "retrieve connection strings. At subscription scope this is data-plane pivot."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt)
            is_sql_contrib = (
                role in SQL_ROLE_TOKENS
                or any(guid in role for guid in SQL_ROLE_GUIDS)
            )
            if not is_sql_contrib:
                continue
            scope = _scope_token(stmt)
            if scope.startswith("/subscriptions/") and "/providers/Microsoft.Sql/" not in scope:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = {role!r}, scope = {scope!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Scope SQL Contributor to the individual SQL server resource. "
                            "For management-only access, prefer Entra ID-only authentication "
                            "and assign Reader; for schema migrations use a managed identity "
                            "with a DbOwner grant at the database level."
                        ),
                        framework_refs=[
                            "CIS_AZURE_4_1",
                            "NIST_AC_6",
                            "MITRE_T1212",
                        ],
                    )
                )
        return findings
