"""AZURE005: Storage Blob Data Contributor granted at subscription scope.

`Storage Blob Data Contributor` is the Azure data-plane role that grants
read/write/list on the contents of Azure Storage containers and blobs.
Granting it at subscription scope means the principal can read or overwrite
the contents of every storage account in the subscription - including
CloudTrail-equivalent activity logs and Terraform state blobs.
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
class StorageBlobContributorWildcardRule(Rule):
    rule_id = "AZURE005"
    title = "Storage Blob Data Contributor at subscription scope - blanket blob access"
    severity = Severity.HIGH
    provider = Provider.AZURE
    description = (
        "Storage Blob Data Contributor grants read/write/list on Azure Storage contents "
        "of the scope it's held against. At subscription scope this means the principal can "
        "overwrite every blob in every storage account, including audit/state artifacts."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt)
            is_blob_contrib = (
                role == "storage blob data contributor"
                or "storageblobdatacontributor" in role.replace("-", "")
                or "ba92f5b4-2d11-453d-a403-e96b0029c9fe" in role
            )
            if not is_blob_contrib:
                continue
            scope = _scope_token(stmt)
            if scope.startswith("/subscriptions/") and "/resourceGroups/" not in scope:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = 'Storage Blob Data Contributor', scope = {scope!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Constrain the role to a single storage account. For read-only "
                            "access (e.g. analytics), prefer 'Storage Blob Data Reader'. For "
                            "audit/Exports containers, prefer a managed identity with a "
                            "container-scoped SAS-via-credential rotations strategy."
                        ),
                        framework_refs=[
                            "CIS_AZURE_3_7",
                            "NIST_SC_28",
                            "MITRE_T1530",
                        ],
                    )
                )
        return findings
