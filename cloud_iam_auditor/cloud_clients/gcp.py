"""GCP live-mode fetcher via google-cloud-resourcemanager.

Reads a project's IAM bindings using Application Default Credentials via the
ResourceManager v3 API. The google-cloud SDK is imported locally so users
without the `live` extra get a clean `MissingDependencyError`.
"""

from __future__ import annotations

from ..loader import LoadedPolicy, load_policy_from_data
from .errors import ApiCallError, MissingDependencyError, NoCredentialsError


def _resourcemanager():
    try:
        from google.cloud import resourcemanager_v3  # type: ignore
        return resourcemanager_v3
    except ImportError as exc:  # pragma: no cover - dep error path
        raise MissingDependencyError.for_live("google-cloud-resourcemanager") from exc


def fetch_project_bindings(project_id: str) -> LoadedPolicy:
    """Fetch IAM bindings for a single GCP project.

    Mirrors `gcloud projects get-iam-policy`: returns the project-level IAM
    policy as a `bindings` array, suitable for direct feed into the rule
    engine via `load_policy_from_data`.
    """
    rm = _resourcemanager()
    try:
        client = rm.ProjectsClient()
    except Exception as exc:  # noqa: BLE001
        raise NoCredentialsError.for_gcp(str(exc)) from exc

    project_name = f"projects/{project_id}"
    try:
        response = client.get_iam_policy(request={"resource": project_name})
        bindings = [
            {"role": b.role, "members": list(b.members)}
            for b in response.bindings
        ]
        return load_policy_from_data(
            {"bindings": bindings},
            source_label=f"gcp:{project_id}",
        )
    except Exception as exc:  # noqa: BLE001 - convert to typed errors
        msg = str(exc).lower()
        if "default credentials" in msg or "could not automatically determine credentials" in msg:
            raise NoCredentialsError.for_gcp(str(exc)) from exc
        raise ApiCallError(f"GCP get_iam_policy failed for {project_id}: {exc}") from exc


__all__ = ["fetch_project_bindings"]
