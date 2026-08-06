"""GCP002: Public (`allUsers` / `allAuthenticatedUsers`) granted ANY role."""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import gcp_registry

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


@gcp_registry.register
class PublicAnyRoleRule(Rule):
    rule_id = "GCP002"
    title = "Public member granted a GCP role (verify intent)"
    severity = Severity.HIGH
    provider = Provider.GCP
    description = (
        "A GCP binding grants any role to allUsers / allAuthenticatedUsers. Even a "
        "low-privilege role exposed publicly can leak metadata or enable enumeration; "
        "flag for human review."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, binding in enumerate(statements):
            role = binding.get("role", "")
            members = binding.get("members", [])
            public = [m for m in members if m in PUBLIC_MEMBERS]
            # GCP001 already handles privileged roles; fire here only for non-privileged ones.
            if public and not any(
                tok in role.lower() for tok in ("owner", "editor", "admin")
            ):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"role = {role!r}, public members = {public!r}",
                        remediation=(
                            "Confirm the public binding is intentional. Prefer binding the "
                            "principal by domain or service-account email instead of allUsers, "
                            "and gate access with an IAM Condition (request.time / resource.path)."
                        ),
                        framework_refs=["CIS_GCP_1_10", "MITRE_T1078_004"],
                    )
                )
        return findings
