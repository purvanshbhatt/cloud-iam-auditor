"""AWS live-mode fetchers via boto3.

Each function returns a sequence of `LoadedPolicy` objects (already-detected
AWS statements). The boto3 import is local to each function so that users
who never installed the `live` extra pay no import cost / receive a clean
`MissingDependencyError` with an install hint instead of a noisy ImportError.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Iterator

from ..loader import LoadedPolicy, load_policy_from_data
from .errors import ApiCallError, MissingDependencyError, NoCredentialsError


def _boto3():
    try:
        import boto3  # type: ignore
    except ImportError as exc:  # pragma: no cover - dep error path
        raise MissingDependencyError.for_live("boto3") from exc
    return boto3


def _iam_client(region: str | None = None, profile: str | None = None):
    """Build an IAM client using boto3's default credential chain.

    boto3 resolves credentials from env vars / ~/.aws/credentials / instance
    metadata / SSO automatically, so the CLI never needs special flags.
    """
    boto3 = _boto3()
    session_kwargs: dict = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region
    try:
        session = boto3.session.Session(**session_kwargs)
    except Exception as exc:  # noqa: BLE001 - surface as NoCredentialsError
        raise NoCredentialsError.for_aws(str(exc)) from exc

    if session.region_name is None and region is None:
        # Default to us-east-1 only if neither caller nor env specified.
        session = boto3.session.Session(region_name="us-east-1", **session_kwargs)
    return session.client("iam")


def fetch_managed_policies(
    scope: str = "Local",
    region: str | None = None,
    profile: str | None = None,
) -> Iterator[LoadedPolicy]:
    """Enumerate IAM managed policies visible to the caller and yield each as a
    `LoadedPolicy`.

    Args:
        scope: "ALL", "AWS", or "LOCAL" (default = customer-managed only).
        region, profile: optional boto3 overrides (None = default chain).
    """
    client = _iam_client(region=region, profile=profile)
    try:
        paginator = client.get_paginator("list_policies")
        for page in paginator.paginate(Scope=scope):
            for pol in page.get("Policies", []):
                arn = pol["Arn"]
                version_id = pol["DefaultVersionId"]
                version = client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                doc_str = version["PolicyVersion"]["Document"]
                if isinstance(doc_str, str):
                    doc = json.loads(urllib.parse.unquote(doc_str))
                else:
                    doc = doc_str
                yield load_policy_from_data(doc, source_label=f"aws:{arn}")
    except Exception as exc:  # noqa: BLE001 - convert to ApiCallError for CLI
        if "AuthFailure" in str(exc) or "ExpiredToken" in str(exc) or "InvalidClientTokenId" in str(exc):
            raise NoCredentialsError.for_aws(str(exc)) from exc
        raise ApiCallError(f"AWS IAM call failed: {exc}") from exc


def fetch_policy_by_arn(
    policy_arn: str,
    region: str | None = None,
    profile: str | None = None,
) -> LoadedPolicy:
    """Fetch the default version document of a single managed policy by ARN."""
    client = _iam_client(region=region, profile=profile)
    try:
        meta = client.get_policy(PolicyArn=policy_arn)
        version_id = meta["Policy"]["DefaultVersionId"]
        version = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc_str = version["PolicyVersion"]["Document"]
        if isinstance(doc_str, str):
            doc = json.loads(urllib.parse.unquote(doc_str))
        else:
            doc = doc_str
        return load_policy_from_data(doc, source_label=f"aws:{policy_arn}")
    except Exception as exc:  # noqa: BLE001
        if "AuthFailure" in str(exc) or "ExpiredToken" in str(exc):
            raise NoCredentialsError.for_aws(str(exc)) from exc
        raise ApiCallError(f"AWS IAM get_policy failed for {policy_arn}: {exc}") from exc


def fetch_role_inline_policies(
    role_name: str,
    region: str | None = None,
    profile: str | None = None,
) -> Iterator[LoadedPolicy]:
    """Fetch all inline policy documents attached to an IAM role."""
    client = _iam_client(region=region, profile=profile)
    try:
        names = client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        for name in names:
            resp = client.get_role_policy(RoleName=role_name, PolicyName=name)
            doc_str = resp["PolicyDocument"]
            if isinstance(doc_str, str):
                doc = json.loads(urllib.parse.unquote(doc_str))
            else:
                doc = doc_str
            yield load_policy_from_data(doc, source_label=f"aws:role/{role_name}:{name}")
    except Exception as exc:  # noqa: BLE001
        if "AuthFailure" in str(exc) or "ExpiredToken" in str(exc):
            raise NoCredentialsError.for_aws(str(exc)) from exc
        raise ApiCallError(f"AWS IAM list/get_role_policy failed for {role_name}: {exc}") from exc


__all__ = [
    "fetch_managed_policies",
    "fetch_policy_by_arn",
    "fetch_role_inline_policies",
]
