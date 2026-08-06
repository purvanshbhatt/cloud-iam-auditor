"""Rule registry: discover, instantiate, and run all detection rules."""

from __future__ import annotations

from ..base import Finding, Rule, Statement


class RuleRegistry:
    """Holds registered rule classes and runs them against policy statements."""

    def __init__(self) -> None:
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


# Module-level singleton; rules register themselves at import time.
registry = RuleRegistry()


def get_registry() -> RuleRegistry:
    return registry


def all_rules() -> dict[str, type[Rule]]:
    return {cls.rule_id: cls for cls in registry.rule_classes()}


# Importing the rule modules below triggers their @registry.register decorators.
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

__all__ = ["RuleRegistry", "registry", "get_registry", "all_rules"]
