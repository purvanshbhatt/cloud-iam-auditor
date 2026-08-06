"""GCP005: `roles/iam.serviceAccountTokenCreator` granted broadly.

`serviceAccountTokenCreator` lets a principal mint short-lived OAuth access tokens
in the name of a service account. A broad binding is an account-wide privilege
escalation primitive - one compromised principal can pivot to impersonate any
account the role is held against.
"""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import gcp_registry

TOKEN_CREATOR_ROLE = "roles/iam.serviceAccountTokenCreator"
THRESHOLD = 2


@gcp_registry.register
class BroadTokenCreatorRule(Rule):
    rule_id = "GCP005"
    title = (
        f"roles/iam.serviceAccountTokenCreator granted to >{THRESHOLD} principals "
        "- token-mint blast radius"
    )
    severity = Severity.HIGH
    provider = Provider.GCP
    description = (
        "serviceAccountTokenCreator lets the holder mint OAuth access tokens acting as the bound "
        "service account - effectively a permanent, broad 'AssumeRole' capability. Granting "
        "this to many principals magnifies credential-exposure risk."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, binding in enumerate(statements):
            if binding.get("role") != TOKEN_CREATOR_ROLE:
                continue
            members = binding.get("members", [])
            # Exclude the SA's own principal (a benign self-binding on its identity).
            external = [m for m in members if not m.startswith("serviceAccount:")]
            if len(external) > THRESHOLD:
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=(
                            f"role = {TOKEN_CREATOR_ROLE!r}, principal count = {len(external)}"
                        ),
                        remediation=(
                            "Restrict token creator to a single deployment principal (e.g. the "
                            "CI/CD runner's service account). For human access, prefer "
                            "short-lived Workload Identity Federation credentials over "
                            "statically-granted token creator bindings."
                        ),
                        framework_refs=["NIST_AC_6", "MITRE_T1550_001", "MITRE_T1098"],
                    )
                )
        return findings
