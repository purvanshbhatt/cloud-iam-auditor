"""Load and normalize AWS / GCP / Azure IAM JSON policy documents.

v0.2.0 introduced AWS + GCP provider auto-detection. v0.3.0 adds Azure
role-assignment support and splits the build step out of `load_policy` so
the live-mode path can reuse it from already-parsed dicts.

Recognized shapes:
- **AWS** (top-level `Statement` key, or wrapped `{"PolicyDocument": {...}}`)
- **GCP** (top-level `bindings` key, e.g. output of `gcloud projects get-iam-policy`)
- **Azure** (top-level `value` array of role assignments, e.g. output of
  `az role assignment list` or the ARM `/roleAssignments` endpoint)
Anything else raises `LoaderError`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

Statement = dict[str, Any]
Binding = dict[str, Any]


class Provider(str, Enum):
    """Cloud provider whose IAM document we are auditing."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class LoaderError(Exception):
    """Raised when the supplied policy file cannot be parsed as a valid IAM policy."""


@dataclass(frozen=True)
class LoadedPolicy:
    """A normalized representation of an AWS / GCP / Azure IAM policy document.

    For AWS, `statements` holds IAM statements. For GCP, `statements` holds
    GCP role bindings. For Azure, `statements` holds role-assignment dicts.
    The same flat list-of-dicts abstraction is reused so rule `evaluate()`
    methods can iterate uniformly.

    `source` is a string label - either the on-disk file path or a synthetic
    live-mode anchor like "aws:arn:..." / "gcp:project-id" / "azure:subscription".
    """

    source: str
    provider: Provider
    version: str
    statements: list[Statement]


def _normalize_aws_statements(raw: dict[str, Any] | list[Any]) -> list[Statement]:
    """Coerce the AWS `Statement` field into a flat list of statement dicts."""
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        out: list[Statement] = []
        for item in raw:
            if not isinstance(item, dict):
                raise LoaderError(
                    f"Each AWS statement must be a JSON object, got {type(item).__name__}."
                )
            out.append(item)
        return out
    raise LoaderError(
        f"`Statement` must be an object or array, got {type(raw).__name__}."
    )


def _normalize_gcp_bindings(raw: Any) -> list[Binding]:
    """Coerce the GCP `bindings` field into a flat list of binding dicts."""
    if not isinstance(raw, list):
        raise LoaderError(
            f"GCP `bindings` must be an array, got {type(raw).__name__}."
        )
    out: list[Binding] = []
    for item in raw:
        if not isinstance(item, dict):
            raise LoaderError(
                f"Each GCP binding must be a JSON object, got {type(item).__name__}."
            )
        if "role" not in item or "members" not in item:
            raise LoaderError(
                "Each GCP binding must contain `role` and `members` keys."
            )
        out.append(item)
    return out


def _normalize_azure_assignments(raw: Any) -> list[Binding]:
    """Coerce Azure role-assignment JSON into a flat list of assignment dicts."""
    if isinstance(raw, dict) and "value" in raw and isinstance(raw["value"], list):
        raw = raw["value"]
    if not isinstance(raw, list):
        raise LoaderError(
            f"Azure role assignments must be an array or `{{value: [...]}}`, got {type(raw).__name__}."
        )
    out: list[Binding] = []
    for item in raw:
        if not isinstance(item, dict):
            raise LoaderError(
                f"Each Azure role assignment must be a JSON object, got {type(item).__name__}."
            )
        if "roleDefinitionId" not in item or "principalId" not in item:
            raise LoaderError(
                "Each Azure role assignment must contain `roleDefinitionId` and `principalId`."
            )
        out.append(item)
    return out


def _detect_provider(data: dict[str, Any]) -> Provider:
    """Sniff the top-level JSON object and return the inferred provider enum."""
    if "Statement" in data or "PolicyDocument" in data:
        return Provider.AWS
    if "bindings" in data:
        return Provider.GCP
    if "value" in data and isinstance(data["value"], list):
        # Heuristic: at least one entry looks like a role assignment.
        if any(
            isinstance(item, dict)
            and "roleDefinitionId" in item
            and "principalId" in item
            for item in data["value"]
        ):
            return Provider.AZURE
    return Provider.UNKNOWN


def _build_loaded_policy_from_data(data: Any, source: str | Path) -> LoadedPolicy:
    """Build a `LoadedPolicy` from an already-parsed dict. Shared by file + live modes."""
    if not isinstance(data, dict):
        raise LoaderError(
            f"Top-level JSON must be an object, got {type(data).__name__}."
        )

    provider = _detect_provider(data)
    if provider == Provider.UNKNOWN:
        raise LoaderError(
            "Unrecognized IAM policy shape. Expected an AWS document "
            "(top-level `Statement` or `PolicyDocument`), a GCP document "
            "(top-level `bindings`), or an Azure role-assignment document "
            "(top-level `value` array of role assignments)."
        )

    if provider == Provider.AWS:
        # Unwrap if the caller gave us the AWS GetPolicyVersion response shape.
        if "PolicyDocument" in data and isinstance(data["PolicyDocument"], dict):
            data = data["PolicyDocument"]
        version = str(data.get("Version", "2012-10-17"))
        statements = _normalize_aws_statements(data.get("Statement", []))
        return LoadedPolicy(
            source=str(source), provider=Provider.AWS, version=version, statements=statements
        )

    if provider == Provider.GCP:
        return LoadedPolicy(
            source=str(source),
            provider=Provider.GCP,
            version="v1",
            statements=_normalize_gcp_bindings(data["bindings"]),
        )

    # provider == Provider.AZURE
    return LoadedPolicy(
        source=str(source),
        provider=Provider.AZURE,
        version="2022-04-01",
        statements=_normalize_azure_assignments(data),
    )


def load_policy(file_path: str | Path) -> LoadedPolicy:
    """Read an IAM policy JSON file, auto-detect provider, and return a normalized
    `LoadedPolicy`.

    Accepts:
      - AWS: `{"Version": "...", "Statement": [...]}` or wrapped
        `{"PolicyDocument": {...}, "PolicyName": "..."}`.
      - GCP: `{"bindings": [{"role": "roles/X", "members": [...]}, ...]}`.
      - Azure: `{"value": [{"roleDefinitionId": "...", "principalId": "..."}, ...]}`.
    """
    path = Path(file_path)
    if not path.exists():
        raise LoaderError(f"File not found: {path}")
    if not path.is_file():
        raise LoaderError(f"Not a file: {path}")
    if path.suffix.lower() not in {".json", ".iam", ".policy", ".yaml", ".yml"}:
        raise LoaderError(
            f"Expected a JSON file (.json), got extension '{path.suffix}'."
        )

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LoaderError(f"Unable to read {path}: {exc}") from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"Invalid JSON in {path}: {exc}") from exc

    return _build_loaded_policy_from_data(data, source=path)


def load_policy_from_data(data: Any, source_label: str = "<live>") -> LoadedPolicy:
    """Build a `LoadedPolicy` from an already-parsed dict (used by live mode).

    `source_label` is a synthetic string used in the report title when there
    is no on-disk file backing the policy (e.g. "aws-account").
    """
    return _build_loaded_policy_from_data(data, source=source_label)
