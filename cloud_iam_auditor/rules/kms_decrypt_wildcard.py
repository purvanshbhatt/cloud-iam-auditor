"""IAM009: kms:Decrypt granted against any resource ('*')."""

from __future__ import annotations

from ..base import Finding, Rule, Severity, Statement
from ..rules.registry import registry


def _is_wildcard(value) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


def _contains_kms_decrypt(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        v = value.lower()
        return v == "*" or v == "kms:decrypt" or v == "kms:*" or v == "kms:decrypt*"
    if isinstance(value, list):
        return any(
            isinstance(v, str)
            and (v == "*" or v.lower() in {"kms:decrypt", "kms:*"} or v.lower().startswith("kms:decrypt"))
            for v in value
        )
    return False


@registry.register
class KmsDecryptWildcardRule(Rule):
    rule_id = "IAM009"
    title = "kms:Decrypt granted on wildcard ('*') Resource - blanket KMS access"
    severity = Severity.HIGH
    description = (
        "An Allow statement grants kms:Decrypt (or kms:*) against '*' - the holder can decrypt "
        "any ciphertext encrypted with any KMS key in the account they can address, defeating "
        "PII / secrets isolation."
    )

    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        findings: list[Finding] = []
        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue
            if not _contains_kms_decrypt(stmt.get("Action")):
                continue
            resource = stmt.get("Resource")
            if _is_wildcard(resource) or (
                isinstance(resource, list)
                and any(r == "*" or r.endswith(":*") for r in resource if isinstance(r, str))
            ):
                findings.append(
                    self._finding(
                        statement_index=idx,
                        evidence=f"Action includes kms:Decrypt, Resource = {resource!r}",
                        remediation=(
                            "Restrict Resource to specific KMS key ARNs the principal needs to "
                            "use, and add a kms:ViaService Condition to bind the key to a single "
                            "consumer service (e.g. ssm, secretsmanager, s3, rds)."
                        ),
                        framework_refs=["NIST_SC_12", "CIS_2_8"],
                    )
                )
        return findings
