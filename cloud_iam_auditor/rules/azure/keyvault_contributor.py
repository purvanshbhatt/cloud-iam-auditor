"""AZURE004: Key Vault Contributor granted at subscription or resource-group scope.

`Key Vault Contributor` lets the holder modify Key Vault access policies / RBAC
assignments, effectively granting read access to any secret/key/certificate
inside that vault without ever holding a data-plane role. This is the Azure
equivalent of `kms:Decrypt` on a wildcard resource (AWS IAM009).
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
class KeyVaultContributorRule(Rule):
    rule_id = "AZURE004"
    title = "Key Vault Contributor at broad scope - indirect secret access"
    severity = Severity.HIGH
    provider = Provider.AZURE
    description = (
        "Key Vault Contributor lets the holder modify Key Vault access policies, "
        "effectively granting read access to any secret/cert/key it wraps. Granting it "
        "at subscription or resource-group scope widens the data-exposure blast radius."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            role = _role_token(stmt)
            is_kv_contrib = role == "key vault contributor" or role.endswith(
                "f25e1a64-01d0-4a52-ba22-7a027bede7f8"  # /roleDefinitions/<guid>
            )
            if not is_kv_contrib:
                continue
            scope = _scope_token(stmt)
            if not scope:
                # If the assignment doesn't carry a scope (older API shape), still flag.
                broad = True
            else:
                broad = (
                    scope == "/"
                    or scope.startswith("/subscriptions/")
                    and "/providers/Microsoft.KeyVault/vaults/" not in scope
                )
            if broad:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = 'Key Vault Contributor', scope = {scope or '<unknown>'!r}, "
                            f"principal = {stmt.get('principalId')!r}"
                        ),
                        remediation=(
                            "Scope Key Vault Contributor to a single Key Vault resource. "
                            "Prefer the Key Vault data-plane RBAC roles "
                            "(Key Vault Secrets User / Key Vault Secrets Officer) which "
                            "grant data access without letting the holder pivot to other vaults."
                        ),
                        framework_refs=[
                            "CIS_AZURE_8_1",
                            "NIST_SC_12",
                            "MITRE_T1552_001",
                        ],
                    )
                )
        return findings
