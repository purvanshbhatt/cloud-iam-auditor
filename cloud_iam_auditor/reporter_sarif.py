"""SARIF 2.1.0 reporter for GitHub Code Scanning integration.

Emits a SARIF report that GitHub Actions can ingest natively via
`actions/upload-artifact` + the code-scanning SARIF uploader. The schema is
fixed by the OASIS SARIF spec (https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Finding, Severity
from .frameworks import resolve

# Map our low/medium/high/critical severity to the SARIF "level" enum:
# none | note | warning | error. The closest stable mapping is:
#   low -> note
#   medium -> warning
#   high -> error
#   critical -> error
SARIF_LEVEL: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _rule_for(finding: Finding, rule_index_map: dict[str, int]) -> dict:
    """Build (or look up) a `reportingDescriptor` for this finding's rule."""
    if finding.rule_id in rule_index_map:
        # Return only the rule_id reference; full descriptor already emitted.
        return {"index": rule_index_map[finding.rule_id]}

    # First time we see this rule_id; emit a full descriptor.
    framework_tags = [
        resolve(alias).render() for alias in finding.framework_refs
    ] if finding.framework_refs else []
    descriptor = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {
            "text": finding.rule_description or finding.title
        },
        "defaultConfiguration": {
            "level": SARIF_LEVEL[finding.severity],
        },
        "properties": {
            "tags": ["cloud-iam", "zero-trust", *(framework_tags)],
            "precision": "high",
            "security-severity": str(finding.severity.weight * 25),  # 25..100 scale
        },
    }
    rule_index_map[finding.rule_id] = len(rule_index_map)
    return descriptor


def _result_for(finding: Finding, rule_index_map: dict[str, int]) -> dict:
    """Build a single SARIF `result` object."""
    idx = rule_index_map.get(finding.rule_id)
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": idx if idx is not None else 0,
        "level": SARIF_LEVEL[finding.severity],
        "message": {
            "text": finding.title,
            "markdown": (
                f"**{finding.title}**\n\n"
                f"**Evidence:** `{finding.evidence}`\n\n"
                f"**Remediation:** {finding.remediation}"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(finding.statement_index),
                        "uriBaseId": "STATEMENT_INDEX",
                    },
                },
                "logicalLocations": [
                    {
                        "name": "policy",
                        "kind": "object",
                        "properties": {
                            "provider": finding.provider.value if finding.provider else None,
                        },
                    }
                ],
            }
        ],
        "partialFingerprints": {
            "primary/locationLineHash": f"{finding.rule_id}:{finding.statement_index}",
        },
        "properties": {
            "provider": finding.provider.value if finding.provider else None,
            "framework_refs": list(finding.framework_refs),
            "evidence": finding.evidence,
        },
    }


def render_sarif(
    findings: list[Finding],
    source: str,
    tool_version: str = "0.3.0",
) -> str:
    """Render findings as a SARIF 2.1.0 document string.

    Args:
        findings: list of Finding objects to include.
        source: a descriptive label for the audited IAM artifact (used in
            the run's ` automationDetails.guid`).
        tool_version: iam-audit version string (defaults to v0.3.0).
    """
    rule_index_map: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []

    for finding in sorted(findings, key=lambda f: -f.severity.weight):
        # Ensure a rule descriptor exists for this finding's rule_id.
        if finding.rule_id not in rule_index_map:
            descriptor = _rule_for(finding, rule_index_map)
            rules.append(descriptor)
        results.append(_result_for(finding, rule_index_map))

    # Use a hashed source label inside a stable guid segment to avoid
    # special characters in the SARIF automation guid.
    import hashlib

    guid_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]

    doc = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloud-iam-auditor-pb",
                        "version": tool_version,
                        "informationUri": "https://github.com/purvanshbhatt/cloud-iam-auditor",
                        "rules": rules,
                    }
                },
                "automationDetails": {"guid": f"iam-audit-{guid_hash}"},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False)


def render_sarif_to_file(
    findings: list[Finding],
    source: str,
    out_path: str | Path,
    tool_version: str = "0.3.0",
) -> None:
    """Render SARIF and write it to disk."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_sarif(findings, source, tool_version), encoding="utf-8")


__all__ = ["render_sarif", "render_sarif_to_file", "SARIF_LEVEL"]
