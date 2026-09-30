"""Standalone tests for the ported encrypted vault."""

import json
import os

import pytest

from usr.plugins.omaseal.helpers import vault as V


@pytest.fixture()
def vpath(tmp_path):
    return str(tmp_path / "vault.enc")


def test_set_get_roundtrip(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("OPENROUTER_API_KEY", "sk-or-testvalue1234", ["model_provider"])
    assert v.get("OPENROUTER_API_KEY") == "sk-or-testvalue1234"


def test_persists_across_instances(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("KEY_ONE", "value-one-12345")
    v2 = V.FileVault(vpath, master_key="test-master")
    assert v2.get("KEY_ONE") == "value-one-12345"


def test_wrong_master_key_fails(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("KEY_ONE", "value-one-12345")
    v2 = V.FileVault(vpath, master_key="other-master")
    with pytest.raises(Exception):
        v2.get("KEY_ONE")


def test_list_meta_never_returns_values(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("MY_KEY", "super-secret-value-99", ["scope_a"])
    meta = v.list_meta()
    assert meta == [{"name": "MY_KEY", "scopes": ["scope_a"]}]
    assert "super-secret-value-99" not in json.dumps(meta)


def test_file_contains_no_plaintext(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("MY_KEY", "super-secret-value-99")
    raw = open(vpath, encoding="utf-8").read()
    assert "super-secret-value-99" not in raw
    assert "MY_KEY" in raw  # names are not secret


def test_scope_enforcement(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("SCOPED", "scoped-value-123", ["allowed"])
    with pytest.raises(PermissionError):
        v.get("SCOPED", requester_scope="denied")
    assert v.get("SCOPED", requester_scope="allowed") == "scoped-value-123"


def test_delete(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    v.set("GONE", "gone-value-123")
    assert v.delete("GONE") is True
    assert v.get("GONE") is None
    assert v.delete("GONE") is False


def test_missing_file_get_returns_none(vpath):
    v = V.FileVault(vpath, master_key="test-master")
    assert v.get("NOPE") is None
    assert v.exists_on_disk() is False


def test_file_permissions(tmp_path):
    vpath = tmp_path / "vault.enc"
    v = V.FileVault(str(vpath), master_key="test-master")
    v.set("K", "v" * 16)
    if os.name != "nt":
        assert oct(vpath.stat().st_mode & 0o777) == "0o600"


def test_mask_value():
    assert V.mask_value("sk-abc1234567") == "••••••••4567"
    assert V.mask_value("") == ""


def test_redact_values():
    text = "token is abcdefgh-secret and again abcdefgh-secret"
    out = V.redact_values(text, ["abcdefgh-secret"])
    assert "abcdefgh-secret" not in out
    assert out.count("***REDACTED***") == 2
    # short values never masked (spec: min length guard)
    assert V.redact_values("tiny abc", ["abc"]) == "tiny abc"
