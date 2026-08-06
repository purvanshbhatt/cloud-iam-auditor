"""Load and normalize AWS IAM JSON policy documents."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

Statement = Dict[str, Any]


class LoaderError(Exception):
    """Raised when the supplied policy file cannot be parsed as a valid AWS IAM policy."""


@dataclass(frozen=True)
class LoadedPolicy:
    """A normalized representation of an AWS IAM policy document."""

    source: Path
    version: str
    statements: list[Statement]


def _normalize_statements(raw: dict[str, Any] | list[Any]) -> list[Statement]:
    """Coerce the `Statement` field into a flat list of statement dicts.

    AWS allows `Statement` to be either a single object or an array; this helper
    unifies both shapes so rules can iterate uniformly.
    """
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        out: list[Statement] = []
        for item in raw:
            if not isinstance(item, dict):
                raise LoaderError(
                    f"Each statement must be a JSON object, got {type(item).__name__}."
                )
            out.append(item)
        return out
    raise LoaderError(
        f"`Statement` must be an object or array, got {type(raw).__name__}."
    )


def load_policy(file_path: str | Path) -> LoadedPolicy:
    """Read an AWS IAM policy JSON file and return a normalized `LoadedPolicy`.

    Accepts two shapes:
      1. A bare IAM policy document: `{"Version": "...", "Statement": [...]}`.
      2. A wrapped AWS resource record: `{"PolicyDocument": {...}, "PolicyName": "..."}`.
    """
    path = Path(file_path)
    if not path.exists():
        raise LoaderError(f"File not found: {path}")
    if not path.is_file():
        raise LoaderError(f"Not a file: {path}")
    if path.suffix.lower() not in {".json", ".iam", ".policy"}:
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

    # Unwrap if the caller gave us the AWS GetPolicyVersion response shape.
    if "PolicyDocument" in data and isinstance(data["PolicyDocument"], dict):
        data = data["PolicyDocument"]

    version = str(data.get("Version", "2012-10-17"))
    statements = _normalize_statements(data.get("Statement", []))

    return LoadedPolicy(source=path, version=version, statements=statements)
