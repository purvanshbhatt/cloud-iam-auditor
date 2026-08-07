"""Azure live-mode fetcher via azure-identity + azure-mgmt-authorization.

Lists role assignments at the subscription scope, then resolves each
`roleDefinitionId` to its role name and each `principalId` to a principal
display name. The azure SDKs are imported locally so users without the
`azure` extra get a clean `MissingDependencyError`.
"""

from __future__ import annotations

from ..loader import LoadedPolicy, load_policy_from_data
from .errors import ApiCallError, MissingDependencyError, NoCredentialsError


def _azure_identity():
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        return DefaultAzureCredential
    except ImportError as exc:  # pragma: no cover - dep error path
        raise MissingDependencyError.for_azure("azure-identity") from exc


def _auth_client():
    """Construct the azure-mgmt-authorization RoleAssignments client using DefaultAzureCredential."""
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise MissingDependencyError.for_azure("azure-mgmt-authorization") from exc
    DefaultAzureCredential = _azure_identity()

    import os

    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise NoCredentialsError.for_azure(
            "Set AZURE_SUBSCRIPTION_ID to the subscription you want to audit."
        )
    try:
        cred = DefaultAzureCredential()
        return AuthorizationManagementClient(credential=cred, subscription_id=sub_id)
    except Exception as exc:  # noqa: BLE001
        raise NoCredentialsError.for_azure(str(exc)) from exc


def fetch_subscription_assignments() -> LoadedPolicy:
    """List all role assignments in the configured subscription.

    Returns a `LoadedPolicy` whose `statements` are the assignment dicts as
    returned by Azure, with two enrichment fields added:
      - `role_name`: human-readable role name resolved from roleDefinitionId
      - `principal_type`: User/ServicePrincipal/Group/etc resolved from principalId
    Enrichment is best-effort; on failure we set them to None and continue.
    """
    client = _auth_client()
    try:
        assignments = list(client.role_assignments.list())
    except Exception as exc:  # noqa: BLE001
        raise ApiCallError(f"Azure role_assignments.list failed: {exc}") from exc

    # Build a role-definition-name cache so each assignment can carry a
    # readable role name without an extra round-trip per entry.
    role_definitions = {}
    try:
        for rd in client.role_definitions.list(scope="/"):
            role_definitions[rd.id] = rd.role_name
    except Exception:  # noqa: BLE001 - enrichment best-effort
        pass

    value = []
    for a in assignments:
        entry = {
            "id": a.id,
            "name": a.name,
            "roleDefinitionId": a.role_definition_id,
            "principalId": a.principal_id,
            "principalType": getattr(a, "principal_type", None),
            "scope": getattr(a, "scope", None) or _scope_from_id(a.id),
            "role_name": role_definitions.get(a.role_definition_id, None),
        }
        value.append(entry)

    return load_policy_from_data(
        {"value": value},
        source_label="azure:subscription",
    )


def _scope_from_id(assignment_id: str | None) -> str | None:
    """Best-effort extract the management scope string from an ARM assignment ID."""
    if not assignment_id or "/providers/Microsoft.Authorization/roleAssignments/" not in assignment_id:
        return None
    return assignment_id.split("/providers/Microsoft.Authorization/roleAssignments/")[0]


__all__ = ["fetch_subscription_assignments"]
