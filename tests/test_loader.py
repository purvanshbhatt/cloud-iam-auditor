"""Tests for the policy loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloud_iam_auditor.loader import LoaderError, Provider, load_policy


def test_loads_single_statement_policy(fixtures_dir: Path):
    policy = load_policy(fixtures_dir / "benign_policy.json")
    assert policy.version == "2012-10-17"
    assert policy.provider == Provider.AWS
    assert len(policy.statements) == 1
    assert policy.statements[0]["Action"] == "s3:GetObject"


def test_unwraps_wrapped_policy_document(fixtures_dir: Path):
    policy = load_policy(fixtures_dir / "wrapped_policy.json")
    assert policy.provider == Provider.AWS
    assert policy.statements[0]["Action"] == "kms:Decrypt"


def test_detects_gcp_bindings(fixtures_dir: Path):
    policy = load_policy(fixtures_dir / "gcp_benign.json")
    assert policy.provider == Provider.GCP
    assert policy.version == "v1"
    assert len(policy.statements) == 1
    assert policy.statements[0]["role"] == "roles/storage.objectViewer"


def test_unknown_shape_raises(tmp_path: Path):
    bad = tmp_path / "unknown.json"
    bad.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(LoaderError, match="Unrecognized IAM policy shape"):
        load_policy(bad)


def test_gcp_binding_must_have_role_and_members(tmp_path: Path):
    bad = tmp_path / "bad_gcp.json"
    bad.write_text('{"bindings":[{"members":["user:a@x.io"]}]}', encoding="utf-8")
    with pytest.raises(LoaderError, match="must contain `role` and `members`"):
        load_policy(bad)


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(LoaderError, match="File not found"):
        load_policy(tmp_path / "nope.json")


def test_wrong_extension_rejected(fixtures_dir: Path):
    benign = fixtures_dir / "benign_policy.json"
    renamed = benign.with_suffix(".txt")
    renamed.write_bytes(benign.read_bytes())
    with pytest.raises(LoaderError, match="Expected a JSON file"):
        load_policy(renamed)


def test_malformed_json_raises(fixtures_dir: Path):
    with pytest.raises(LoaderError, match="Invalid JSON"):
        load_policy(fixtures_dir / "malformed.json")
