"""IAM003: Attaches the AWS-managed `AdministratorAccess` policy."""

from __future__ import annotations

from ..base import Finding, Provider, Rule, Severity, Statement
from ..rules.registry import registry

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


@registry.register
class AdminManagedPolicyRule(Rule):
    rule_id = "IAM003"
    title = "AWS-managed AdministratorAccess policy attached"
    severity = Severity.CRITICAL
    provider = Provider.AWS
    description = (
        "A policy attachment references arn:aws:iam::aws:policy/AdministratorAccess, granting "
        "unrestricted administrative control over the entire AWS account."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            # Attachment statements often encode the policy ARN under Action or Resource.
            haystack: list[str] = (
                _as_list(stmt.get("Action")) + _as_list(stmt.get("Resource"))
            )
            for entry in haystack:
                if ADMIN_POLICY_ARN in entry or entry == "AdministratorAccess":
                    findings.append(
                        self._finding(
                            statement_index=idx,
                            evidence=f"AdministratorAccess reference found in {entry!r}",
                            remediation=(
                                "Detach AdministratorAccess and replace with the minimum set of "
                                "customer-managed policies required by the workload. Track usage "
                                "with IAM Access Analyzer's unused-access findings."
                            ),
                            framework_refs=["NIST_AC_6_5", "CIS_1_16", "MITRE_T1078_004"],
                        )
                    )
                    break
        return findings
