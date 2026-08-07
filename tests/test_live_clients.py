"""Tests for live-mode cloud_clients using monkeypatched stub SDKs.

We do NOT install boto3/google-cloud/azure-* in the dev test env. Instead we
install lightweight stub modules into sys.modules at runtime so the live-mode
code paths can be exercised without any network or real cloud creds.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from cloud_iam_auditor.cloud_clients.errors import (
    MissingDependencyError,
    NoCredentialsError,
)

# ============================================================================
# AWS cloud_clients stubs
# ============================================================================


def _install_boto3_stub(monkeypatch, list_policies_pages=None, get_policy_meta=None,
                       get_policy_version_doc=None, list_role_policies_names=None,
                       get_role_policy_doc=None, raise_on_session: bool = False):
    """Inject a fake `boto3` module so cloud_clients.aws can be imported."""
    boto3_stub = types.ModuleType("boto3")
    session_stub = types.ModuleType("boto3.session")

    class _Session:
        def __init__(self, **kwargs):
            if raise_on_session:
                raise RuntimeError("no creds")
            self.kwargs = kwargs
            self.region_name = kwargs.get("region_name", "us-east-1")

        def client(self, service):
            iam = MagicMock()
            if list_policies_pages is not None:
                paginator = MagicMock()
                paginator.paginate.return_value = list_policies_pages
                iam.get_paginator.return_value = paginator
            if get_policy_meta is not None:
                iam.get_policy.return_value = get_policy_meta
            if get_policy_version_doc is not None:
                iam.get_policy_version.return_value = get_policy_version_doc
            if list_role_policies_names is not None:
                iam.list_role_policies.return_value = {"PolicyNames": list_role_policies_names}
            if get_role_policy_doc is not None:
                iam.get_role_policy.return_value = {"PolicyDocument": get_role_policy_doc}
            return iam

    session_stub.Session = _Session
    boto3_stub.session = session_stub
    boto3_stub.session.Session = _Session  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "boto3", boto3_stub)
    monkeypatch.setitem(sys.modules, "boto3.session", session_stub)


def test_aws_fetch_policy_by_arn_returns_loaded_policy(monkeypatch):
    arn = "arn:aws:iam::111:policy/example"
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    _install_boto3_stub(
        monkeypatch,
        get_policy_meta={"Policy": {"DefaultVersionId": "v1"}},
        get_policy_version_doc={"PolicyVersion": {"Document": doc}},
    )
    from cloud_iam_auditor.cloud_clients.aws import fetch_policy_by_arn

    loaded = fetch_policy_by_arn(arn)
    assert loaded.provider.value == "aws"
    assert loaded.source == f"aws:{arn}", f"got source = {loaded.source!r}"
    assert loaded.statements[0]["Action"] == "*"


def test_aws_fetch_managed_policies_iterates(monkeypatch):
    docs = [
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"}]},
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    ]
    pages = [
        {"Policies": [
            {"Arn": "arn:pol1", "DefaultVersionId": "v1"},
            {"Arn": "arn:pol2", "DefaultVersionId": "v2"},
        ]},
    ]

    def fake_get_policy_version(PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": docs.pop(0)}}

    boto3_stub = types.ModuleType("boto3")
    session_stub = types.ModuleType("boto3.session")

    class _Session:
        def __init__(self, **kwargs):
            self.region_name = kwargs.get("region_name", "us-east-1")

        def client(self, service):
            iam = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = pages
            iam.get_paginator.return_value = paginator
            iam.get_policy_version.side_effect = fake_get_policy_version
            return iam

    session_stub.Session = _Session
    boto3_stub.session = session_stub
    boto3_stub.session.Session = _Session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3_stub)
    monkeypatch.setitem(sys.modules, "boto3.session", session_stub)

    from cloud_iam_auditor.cloud_clients.aws import fetch_managed_policies

    results = list(fetch_managed_policies(scope="Local"))
    assert len(results) == 2
    assert {str(p.source) for p in results} == {"aws:arn:pol1", "aws:arn:pol2"}


def test_aws_no_credentials_raises(monkeypatch):
    _install_boto3_stub(monkeypatch, raise_on_session=True)
    from cloud_iam_auditor.cloud_clients.aws import fetch_policy_by_arn

    with pytest.raises(NoCredentialsError):
        fetch_policy_by_arn("arn:aws:iam::111:policy/x")


def test_aws_missing_boto3_raises_clean_error(monkeypatch):
    """When boto3 is NOT installed, users should get MissingDependencyError not ImportError."""
    monkeypatch.delitem(sys.modules, "boto3", raising=False)
    monkeypatch.delitem(sys.modules, "boto3.session", raising=False)
    # Bypass any cached import inside cloud_clients.aws (it's lazy so always re-imported).
    import importlib

    from cloud_iam_auditor.cloud_clients import aws as aws_mod

    # Ensure sys.modules doesn't expose boto3 for the call.
    aws_mod_reloaded = importlib.reload(aws_mod)
    with pytest.raises(MissingDependencyError) as exc:
        aws_mod_reloaded.fetch_policy_by_arn("arn:x")
    assert "pip install cloud-iam-auditor-pb[live]" in str(exc.value)


# ============================================================================
# GCP cloud_clients stubs
# ============================================================================


def _install_gcp_stub(monkeypatch, bindings=None, raise_on_client: bool = False):
    rm_stub = types.ModuleType("google.cloud.resourcemanager_v3")
    rm_v3_inner = types.ModuleType("google.cloud.resourcemanager_v3")

    class _Binding:
        def __init__(self, role, members):
            self.role = role
            self.members = members

    class _Policy:
        def __init__(self, binding_dicts):
            self.bindings = [_Binding(b["role"], b["members"]) for b in binding_dicts]

    class _ProjectsClient:
        def __init__(self):
            if raise_on_client:
                raise RuntimeError("Default credentials failed")

        def get_iam_policy(self, request=None):
            return _Policy(bindings or [])

    rm_v3_inner.ProjectsClient = _ProjectsClient
    rm_stub.ProjectsClient = _ProjectsClient
    rm_stub._inner = rm_v3_inner

    # google.cloud namespace
    google_pkg = types.ModuleType("google")
    google_cloud_pkg = types.ModuleType("google.cloud")
    rm_pkg = types.ModuleType("google.cloud.resourcemanager_v3")
    rm_pkg.ProjectsClient = _ProjectsClient
    google_cloud_pkg.resourcemanager_v3 = rm_pkg
    google_pkg.cloud = google_cloud_pkg

    monkeypatch.setitem(sys.modules, "google", google_pkg)
    monkeypatch.setitem(sys.modules, "google.cloud", google_cloud_pkg)
    monkeypatch.setitem(sys.modules, "google.cloud.resourcemanager_v3", rm_pkg)


def test_gcp_fetch_project_bindings(monkeypatch):
    _install_gcp_stub(
        monkeypatch,
        bindings=[
            {"role": "roles/owner", "members": ["user:x@y.io", "allUsers"]},
        ],
    )
    from cloud_iam_auditor.cloud_clients.gcp import fetch_project_bindings

    policy = fetch_project_bindings("my-proj")
    assert policy.provider.value == "gcp"
    assert policy.source == "gcp:my-proj"
    assert policy.statements[0]["role"] == "roles/owner"
    assert "allUsers" in policy.statements[0]["members"]


def test_gcp_no_credentials_raises(monkeypatch):
    _install_gcp_stub(monkeypatch, raise_on_client=True)
    from cloud_iam_auditor.cloud_clients.gcp import fetch_project_bindings

    with pytest.raises(NoCredentialsError):
        fetch_project_bindings("my-proj")


def test_gcp_missing_sdk_raises_clean_error(monkeypatch):
    monkeypatch.delitem(sys.modules, "google", raising=False)
    monkeypatch.delitem(sys.modules, "google.cloud", raising=False)
    monkeypatch.delitem(sys.modules, "google.cloud.resourcemanager_v3", raising=False)
    import importlib

    from cloud_iam_auditor.cloud_clients import gcp as gcp_mod

    gcp_reloaded = importlib.reload(gcp_mod)
    with pytest.raises(MissingDependencyError) as exc:
        gcp_reloaded.fetch_project_bindings("p")
    assert "pip install cloud-iam-auditor-pb[live]" in str(exc.value)


# ============================================================================
# Azure cloud_clients stubs
# ============================================================================


def _install_azure_stub(monkeypatch, assignments=None, raise_on_client: bool = False,
                       subscription_id: str | None = "11111111-2222-3333-4444-555555555555"):

    if subscription_id is None:
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    else:
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", subscription_id)

    azure_pkg = types.ModuleType("azure")
    azure_identity_pkg = types.ModuleType("azure.identity")
    azure_mgmt_pkg = types.ModuleType("azure.mgmt.authorization")
    types.ModuleType("azure.mgmt.authorization")

    class _DefaultAzureCredential:
        def __init__(self):
            if raise_on_client:
                raise RuntimeError("DefaultAzureCredential failed to find any credential")

    azure_identity_pkg.DefaultAzureCredential = _DefaultAzureCredential

    class _RoleAssignmentsInner:
        def __init__(self, assignments):
            self._assignments = assignments

        def list(self):
            return iter(self._assignments)

    class _RoleDefinitionStub:
        def __init__(self, role_id, role_name):
            self.id = role_id
            self.role_name = role_name

    class _RoleDefinitionsInner:
        def __init__(self, assignments):
            self._by_id = {
                a.role_definition_id: a.role_name or a.role_definition_id
                for a in (assignments or [])
                if a.role_definition_id
            }

        def list(self, scope):
            return iter(
                _RoleDefinitionStub(rd_id, name)
                for rd_id, name in self._by_id.items()
            )

    class _RoleAssignmentsClient:
        def __init__(self, credential, subscription_id):
            self.role_assignments = _RoleAssignmentsInner(assignments or [])
            self.role_definitions = _RoleDefinitionsInner(assignments or [])

    real_client = types.ModuleType("azure.mgmt.authorization")
    real_client.AuthorizationManagementClient = _RoleAssignmentsClient
    azure_pkg.identity = azure_identity_pkg
    azure_mgmt_pkg.authorization = real_client

    monkeypatch.setitem(sys.modules, "azure", azure_pkg)
    monkeypatch.setitem(sys.modules, "azure.identity", azure_identity_pkg)
    monkeypatch.setitem(sys.modules, "azure.mgmt", azure_mgmt_pkg)
    monkeypatch.setitem(sys.modules, "azure.mgmt.authorization", real_client)


class _AssignmentStub:
    def __init__(self, role_definition_id, principal_id, scope, role_name=None,
                 principal_type="User", aid=None, name=None):
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.scope = scope
        self.role_name = role_name
        self.principal_type = principal_type
        self.id = aid or "/x/Microsoft.Authorization/roleAssignments/test-r1"
        self.name = name or "test-r1"


def test_azure_fetch_subscription_assignments(monkeypatch):
    _install_azure_stub(
        monkeypatch,
        assignments=[
            _AssignmentStub(
                role_definition_id="/x/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe2c4fcb611",
                principal_id="user-p1",
                scope="/subscriptions/aa",
                role_name="Owner",
            ),
        ],
    )
    from cloud_iam_auditor.cloud_clients.azure import fetch_subscription_assignments

    policy = fetch_subscription_assignments()
    assert policy.provider.value == "azure"
    assert policy.source == "azure:subscription"
    assert policy.statements[0]["role_name"] == "Owner"
    assert policy.statements[0]["scope"] == "/subscriptions/aa"


def test_azure_no_subscription_id_raises(monkeypatch):
    _install_azure_stub(monkeypatch, subscription_id=None)
    from cloud_iam_auditor.cloud_clients.azure import fetch_subscription_assignments

    with pytest.raises(NoCredentialsError):
        fetch_subscription_assignments()


def test_azure_missing_sdk_raises_clean_error(monkeypatch):
    monkeypatch.delitem(sys.modules, "azure", raising=False)
    monkeypatch.delitem(sys.modules, "azure.identity", raising=False)
    monkeypatch.delitem(sys.modules, "azure.mgmt", raising=False)
    monkeypatch.delitem(sys.modules, "azure.mgmt.authorization", raising=False)
    import importlib

    from cloud_iam_auditor.cloud_clients import azure as az_mod

    az_reloaded = importlib.reload(az_mod)
    with pytest.raises(MissingDependencyError) as exc:
        az_reloaded.fetch_subscription_assignments()
    assert "pip install cloud-iam-auditor-pb[azure]" in str(exc.value)


# ============================================================================
# Live commands smoke tests
# ============================================================================


def test_cli_aws_policy_live_command_runs(monkeypatch):
    """iam-audit aws-policy ARN --json should drive the live path through to JSON output."""
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    _install_boto3_stub(
        monkeypatch,
        get_policy_meta={"Policy": {"DefaultVersionId": "v1"}},
        get_policy_version_doc={"PolicyVersion": {"Document": doc}},
    )
    from typer.testing import CliRunner

    from cloud_iam_auditor.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["aws-policy", "arn:aws:iam::111:policy/test", "--json"])
    assert result.exit_code == 0, result.output
    import json as jsonmod
    payload = jsonmod.loads(result.stdout)
    assert payload["summary"]["by_provider"]["aws"] >= 1
    ids = {f["rule_id"] for f in payload["findings"]}
    # Wildcard action AND wildcard resource should both fire on this doc.
    assert "IAM001" in ids
    assert "IAM002" in ids


def test_cli_aws_policy_live_with_sarif_format_writes_valid_sarif(monkeypatch):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    _install_boto3_stub(
        monkeypatch,
        get_policy_meta={"Policy": {"DefaultVersionId": "v1"}},
        get_policy_version_doc={"PolicyVersion": {"Document": doc}},
    )
    import json as jsonmod

    from typer.testing import CliRunner

    from cloud_iam_auditor.main import app
    runner = CliRunner()
    result = runner.invoke(app, ["aws-policy", "arn:aws:iam::111:policy/test", "--format", "sarif"])
    assert result.exit_code == 0, result.output
    doc = jsonmod.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "cloud-iam-auditor-pb"
    assert len(doc["runs"][0]["results"]) >= 1


def test_cli_gcp_project_live_command_runs(monkeypatch):
    _install_gcp_stub(
        monkeypatch,
        bindings=[{"role": "roles/owner", "members": ["allUsers"]}],
    )
    import json as jsonmod

    from typer.testing import CliRunner

    from cloud_iam_auditor.main import app
    runner = CliRunner()
    result = runner.invoke(app, ["gcp-project", "myproj", "--json"])
    assert result.exit_code == 0, result.output
    payload = jsonmod.loads(result.stdout)
    assert payload["summary"]["by_provider"]["gcp"] >= 1
    ids = {f["rule_id"] for f in payload["findings"]}
    assert "GCP001" in ids


def test_cli_azure_live_command_runs(monkeypatch):
    _install_azure_stub(
        monkeypatch,
        assignments=[
            _AssignmentStub(
                role_definition_id="/x/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe2c4fcb611",
                principal_id="p1",
                scope="/subscriptions/aa",
                role_name="Owner",
            ),
        ],
    )
    import json as jsonmod

    from typer.testing import CliRunner

    from cloud_iam_auditor.main import app
    runner = CliRunner()
    result = runner.invoke(app, ["azure-subscription", "--json"])
    assert result.exit_code == 0, result.output
    payload = jsonmod.loads(result.stdout)
    assert payload["summary"]["by_provider"]["azure"] >= 1
    ids = {f["rule_id"] for f in payload["findings"]}
    assert "AZURE002" in ids
