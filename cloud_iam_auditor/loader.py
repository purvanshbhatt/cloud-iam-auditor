"""Load and normalize AWS / GCP IAM JSON policy documents.

v0.2.0 introduces provider auto-detection. The loader inspects the shape of the
JSON document and tags the returned `LoadedPolicy` with a `Provider` enum that
the CLI uses to dispatch to the correct rule registry.

Recognized shapes:
- **AWS** (top-level `Statement` key, or wrapped `{"PolicyDocument": {...}}`)
- **GCP** (top-level `bindings` key, e.g. output of `gcloud projects get-iam-policy`)
Anything else raises `LoaderError`}.
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
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class LoaderError(Exception):
    """Raised when the supplied policy file cannot be parsed as a valid IAM policy."""


@dataclass(frozen=True)
class LoadedPolicy:
    """A normalized representation of an AWS or GCP IAM policy document.

    For AWS, `statements` holds IAM statements. For GCP, `statements` holds
    GCP role bindings - the same flat list of dicts abstraction is reused so
    that rule `evaluate()` methods can iterate uniformly.
    """

    source: Path
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


def _detect_provider(data: dict[str, Any]) -> Provider:
    """Sniff the top-level JSON object and return the inferred provider enum."""
    if "Statement" in data or "PolicyDocument" in data:
        return Provider.AWS
    if "bindings" in data:
        return Provider.GCP
    return Provider.UNKNOWN


def load_policy(file_path: str | Path) -> LoadedPolicy:
    """Read an IAM policy JSON file, auto-detect provider, and return a normalized
    `LoadedPolicy`.

    Accepts:
      - AWS: `{"Version": "...", "Statement": [...]}` or wrapped
        `{"PolicyDocument": {...}, "PolicyName": "..."}`.
      - GCP: `{"bindings": [{"role": "roles/X", "members": [...]}, ...]}`.
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

    if not isinstance(data, dict):
        raise LoaderError(
            f"Top-level JSON must be an object, got {type(data).__name__}."
        )

    provider = _detect_provider(data)
    if provider == Provider.UNKNOWN:
        raise LoaderError(
            "Unrecognized IAM policy shape. Expected an AWS document "
            "(top-level `Statement` or `PolicyDocument`) or a GCP document "
            "(top-level `bindings`)."
        )

    if provider == Provider.AWS:
        # Unwrap if the caller gave us the AWS GetPolicyVersion response shape.
        if "PolicyDocument" in data and isinstance(data["PolicyDocument"], dict):
            data = data["PolicyDocument"]
        version = str(data.get("Version", "2012-10-17"))
        statements = _normalize_aws_statements(data.get("Statement", []))
        return LoadedPolicy(
            source=path, provider=Provider.AWS, version=version, statements=statements
        )

    # provider == Provider.GCP
    # GCP IAM policies don't expose a Version field; static value for stable output.
    return LoadedPolicy(
        source=path,
        provider=Provider.GCP,
        version="v1",
        statements=_normalize_gcp_bindings(data["bindings"]),
    )
