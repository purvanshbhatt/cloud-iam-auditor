"""Per-provider rule registries (AWS, GCP).

v0.1.0 used a single global `registry`. v0.2.0 splits it into two scoped
registries so AWS rules never evaluate GCP bindings (and vice versa).

For backward compatibility, the legacy module-level name `registry` is kept
as an alias for `aws_registry` so existing AWS rule modules can keep doing
`from ..rules.registry import registry` unchanged.
"""

from __future__ import annotations

from ..base import Finding, Rule, Statement


class RuleRegistry:
    """Holds registered rule classes for a single cloud provider."""

    def __init__(self, provider: str = "") -> None:
        self.provider = provider
        self._rule_classes: list[type[Rule]] = []

    def register(self, rule_cls: type[Rule]) -> type[Rule]:
        """Class decorator registering a rule; idempotent on duplicate registration."""
        if rule_cls not in self._rule_classes:
            self._rule_classes.append(rule_cls)
        return rule_cls

    def rule_classes(self) -> list[type[Rule]]:
        return list(self._rule_classes)

    def instantiate_all(self) -> list[Rule]:
        return [cls() for cls in self._rule_classes]

    def run_all(self, statements: list[Statement]) -> list[Finding]:
        """Run every registered rule against the statements. Order is preserved."""
        findings: list[Finding] = []
        for rule in self.instantiate_all():
            found = rule.evaluate(statements)
            findings.extend(found)
        return findings


# Three scoped singletons. AWS rules register with aws_registry; GCP rules with
# gcp_registry; Azure rules with azure_registry.
aws_registry = RuleRegistry(provider="aws")
gcp_registry = RuleRegistry(provider="gcp")
azure_registry = RuleRegistry(provider="azure")

# Backward-compat alias for v0.1.x AWS rule modules:
# `from ..rules.registry import registry; @registry.register`
registry = aws_registry


def get_aws_registry() -> RuleRegistry:
    return aws_registry


def get_gcp_registry() -> RuleRegistry:
    return gcp_registry


def get_azure_registry() -> RuleRegistry:
    return azure_registry


def all_aws_rules() -> dict[str, type[Rule]]:
    return {cls.rule_id: cls for cls in aws_registry.rule_classes()}


def all_gcp_rules() -> dict[str, type[Rule]]:
    return {cls.rule_id: cls for cls in gcp_registry.rule_classes()}


def all_azure_rules() -> dict[str, type[Rule]]:
    return {cls.rule_id: cls for cls in azure_registry.rule_classes()}


# v0.1.x-compat aggregator: returns AWS rules only (mirrors v0.1.0 behavior).
def all_rules() -> dict[str, type[Rule]]:
    return all_aws_rules()


# --- Trigger rule registration by importing each rule module. ----------------
# AWS rules (v0.1.0):
from . import (  # noqa: E402
    admin_managed_policy,  # noqa: F401
    iam_passrole,  # noqa: F401
    kms_decrypt_wildcard,  # noqa: F401
    missing_condition,  # noqa: F401
    not_action_abuse,  # noqa: F401
    not_resource_abuse,  # noqa: F401
    s3_put_object_wildcard,  # noqa: F401
    sts_assume_role_wildcard,  # noqa: F401
    wildcard_action,  # noqa: F401
    wildcard_resource,  # noqa: F401
)

# Azure rules (v0.3.0):
from .azure import (  # noqa: E402
    aks_cluster_admin,  # noqa: F401
    broken_condition_on_elevated_role,  # noqa: F401
    classic_administrator,  # noqa: F401
    keyvault_contributor,  # noqa: F401
    owner_on_subscription,  # noqa: F401
    sql_server_admin,  # noqa: F401
    storage_blob_contributor_wildcard,  # noqa: F401
    user_access_admin_on_subscription,  # noqa: F401
)

# GCP rules (v0.2.0):
from .gcp import (  # noqa: E402
    broad_service_account_user,  # noqa: F401
    broad_token_creator,  # noqa: F401
    primitive_role_assigned,  # noqa: F401
    public_any_role,  # noqa: F401
    public_privileged_role,  # noqa: F401
)

__all__ = [
    "RuleRegistry",
    "aws_registry",
    "gcp_registry",
    "azure_registry",
    "registry",
    "get_aws_registry",
    "get_gcp_registry",
    "get_azure_registry",
    "all_aws_rules",
    "all_gcp_rules",
    "all_azure_rules",
    "all_rules",
]
