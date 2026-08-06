"""GCP003: `roles/iam.serviceAccountUser` granted to >3 members (SA impersonation blast radius)."""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import gcp_registry

SA_USER_ROLE = "roles/iam.serviceAccountUser"
THRESHOLD = 3


@gcp_registry.register
class BroadServiceAccountUserRule(Rule):
    rule_id = "GCP003"
    title = (
        f"roles/iam.serviceAccountUser granted to >{THRESHOLD} members "
        "(lateral movement via SA impersonation)"
    )
    severity = Severity.MEDIUM
    provider = Provider.GCP
    description = (
        "roles/iam.serviceAccountUser lets a principal impersonate the bound service account. "
        "Granting this role to many principals widens the blast radius - one compromise becomes "
        "account-wide privilege escalation."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, binding in enumerate(statements):
            if binding.get("role") != SA_USER_ROLE:
                continue
            members = binding.get("members", [])
            # Skip if the only members are the SAs themselves (benign self-binding).
            external = [m for m in members if not m.startswith("serviceAccount:")]
            if len(external) > THRESHOLD:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = {SA_USER_ROLE!r}, principal count = {len(external)}"
                        ),
                        remediation=(
                            "Reduce the principal set to the minimum callers that genuinely "
                            "need SA impersonation. For automation, prefer Workload Identity "
                            "Federation tokens with short-lived credentials instead of "
                            "statically binding serviceAccountUser."
                        ),
                        framework_refs=["NIST_AC_6", "MITRE_T1098"],
                    )
                )
        return findings
