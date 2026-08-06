"""GCP004: Legacy primitive role (owner/editor/viewer) granted to a user principal."""

from __future__ import annotations

from ...base import Finding, Provider, Rule, Severity, Statement
from ..registry import gcp_registry

PRIMITIVE_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
}


@gcp_registry.register
class PrimitiveRoleAssignedRule(Rule):
    rule_id = "GCP004"
    title = "GCP primitive role (owner/editor/viewer) granted - violates least privilege"
    severity = Severity.HIGH
    provider = Provider.GCP
    description = (
        "Primitive roles (roles/owner, roles/editor, roles/viewer) grant coarse, project-wide "
        "permissions that span hundreds of services. They are deprecated for production IAM; "
        "Google recommends per-resource or per-product predefined roles instead."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, binding in enumerate(statements):
            if binding.get("role") not in PRIMITIVE_ROLES:
                continue
            members = binding.get("members", [])
            humans_robots = [
                m for m in members
                if m.startswith(("user:", "serviceAccount:", "group:"))
            ]
            if not humans_robots:
                continue
            findings.append(
                self._finding(
                    statement_index=idx,
                    evidence=(
                        f"role = {binding.get('role')!r}, principals = {humans_robots!r}"
                    ),
                    remediation=(
                        "Replace the primitive role with a granular predefined role scoped to "
                        "the resource (e.g. roles/storage.objectViewer, roles/bigquery.dataViewer). "
                        "Track drift via Google Cloud Recommender's IAM bindings recommender."
                    ),
                    framework_refs=["CIS_GCP_1_3", "NIST_AC_6_5", "MITRE_T1078_004"],
                )
            )
        return findings
