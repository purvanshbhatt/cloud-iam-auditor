"""Core data model: Provider, Severity, Finding, and the Rule abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .loader import Provider, Statement


class Severity(str, Enum):
    """Risk severity levels, ordered low->critical for filtering."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Case-insensitive lookup with a helpful error."""
        v = value.strip().lower()
        for member in cls:
            if member.value == v:
                return member
        valid = ", ".join(m.value for m in cls)
        raise ValueError(f"Invalid severity '{value}'. Valid: {valid}.")

    @property
    def weight(self) -> int:
        return {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}[self]

    def __ge__(self, other: Severity) -> bool:
        return self.weight >= other.weight

    def __gt__(self, other: Severity) -> bool:
        return self.weight > other.weight

    def __le__(self, other: Severity) -> bool:
        return self.weight <= other.weight

    def __lt__(self, other: Severity) -> bool:
        return self.weight < other.weight


@dataclass
class Finding:
    """A single auditable issue raised by a rule.

    `provider` tags the cloud (`aws` vs `gcp`) so reports can group / filter
    across mixed-policy inventories. Default is `None` to keep the dataclass
    backwards-compatible with any v0.1.x callers that don't pass it.
    """

    rule_id: str
    severity: Severity
    title: str
    statement_index: int
    evidence: str
    remediation: str
    framework_refs: list[str] = field(default_factory=list)
    rule_description: str | None = None
    provider: Provider | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "provider": self.provider.value if self.provider else None,
            "statement_index": self.statement_index,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "framework_refs": list(self.framework_refs),
            "rule_description": self.rule_description,
        }


class Rule(ABC):
    """Abstract base class for every detection rule in the engine.

    Concrete rules set `provider` so the registry can route findings correctly.
    """

    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    provider: Provider | None = None

    @abstractmethod
    def evaluate(self, statements: list[Statement]) -> list[Finding]:
        """Inspect the list of policy statements / bindings and return any findings."""
        raise NotImplementedError

    def _finding(
        self,
        statement_index: int,
        evidence: str,
        remediation: str,
        framework_refs: list[str] | None = None,
    ) -> Finding:
        """Build a Finding pre-tagged with this rule's metadata + provider."""
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title=self.title,
            statement_index=statement_index,
            evidence=evidence,
            remediation=remediation,
            framework_refs=list(framework_refs or []),
            rule_description=self.description,
            provider=self.provider,
        )


__all__ = ["Provider", "Severity", "Finding", "Rule", "Statement"]
