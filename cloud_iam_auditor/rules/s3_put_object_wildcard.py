"""IAM010: s3:PutObject / s3:* granted on a wildcard S3 bucket ARN ('arn:aws:s3:::*')."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry


def _is_s3_write(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        v = value.lower()
        return v == "*" or v == "s3:*" or v == "s3:putobject" or v == "s3:deleteobject"
    if isinstance(value, list):
        return any(
            isinstance(v, str)
            and (v == "*" or v.lower() in {"s3:*", "s3:putobject"} or v.lower().startswith("s3:putobject"))
            for v in value
        )
    return False


def _is_wildcard_s3(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value == "*" or value.startswith("arn:aws:s3:::*")
    if isinstance(value, list):
        return any(
            isinstance(v, str) and (v == "*" or v.startswith("arn:aws:s3:::*"))
            for v in value
        )
    return False


@registry.register
class S3PutObjectWildcardRule(Rule):
    rule_id = "IAM010"
    title = "s3:PutObject granted on every bucket ('arn:aws:s3:::*')"
    severity = Severity.MEDIUM
    description = (
        "An Allow statement grants s3:PutObject/s3:* against a wildcard S3 ARN, letting the "
        "principal write to any object path in any bucket - enables tampering of assets like "
        "CloudTrail logs, terraform state, or audit exports."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if not _is_s3_write(stmt.get("Action")):
                continue
            resource = stmt.get("Resource")
            if _is_wildcard_s3(resource):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"Action includes s3:PutObject, Resource = {resource!r}",
                        remediation=(
                            "Restrict Resource to the explicit bucket ARNs the principal must "
                            "write, and pair with a Condition enforcing s3:x-amz-acl 'private' or "
                            "an SSE-KMS requirement. Audit CloudTrail/State buckets to exclude "
                            "them from positive allows."
                        ),
                        framework_refs=["NIST_SC_28", "CIS_2_1_5"],
                    )
                )
        return findings
