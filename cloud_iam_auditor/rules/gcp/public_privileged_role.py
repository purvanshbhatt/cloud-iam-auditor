"""GCP001: Public (`allUsers` / `allAuthenticatedUsers`) granted a privileged role."""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ...frameworks import describe  # noqa: F401  (kept for parity / future use)
from ..registry import gcp_registry

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIVILEGED_TOKENS = ("owner", "editor", "admin", "iam.securityAdmin", "iam.accountAdmin")


def _is_privileged(role: str) -> bool:
    rl = role.lower()
    return any(tok in rl for tok in PRIVILEGED_TOKENS)


@gcp_registry.register
class PublicPrivilegedRoleRule(Rule):
    rule_id = "GCP001"
    title = "Public member granted a privileged GCP role"
    severity = Severity.CRITICAL
    provider = Provider.GCP
    description = (
        "A GCP role binding grants a privileged role (owner/editor/admin) to either "
        "'allUsers' or 'allAuthenticatedUsers', exposing the project to any caller on the "
        "internet."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, binding in enumerate(statements):
            role = binding.get("role", "")
            members = binding.get("members", [])
            public = [m for m in members if m in PUBLIC_MEMBERS]
            if public and _is_privileged(role):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"role = {role!r}, public members = {public!r}",
                        remediation=(
                            "Remove allUsers / allAuthenticatedUsers from the binding. If "
                            "public access to a specific resource is genuinely required "
                            "(e.g. a public Cloud Run service), constrain it via IAM "
                            "Conditions on the resource path rather than the project binding."
                        ),
                        framework_refs=["CIS_GCP_1_4", "CIS_GCP_1_5", "MITRE_T1078_004"],
                    )
                )
        return findings
