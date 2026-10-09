"""Vault write path — api handlers and the module CLI (Khan#192)."""

import io
import json
import os

import pytest

from usr.plugins.omaseal.api import secret_delete, secret_list, secret_set
from usr.plugins.omaseal.helpers import resolve as R
from usr.plugins.omaseal.helpers import vault as V

from conftest import run


@pytest.fixture()
def tmp_vault(tmp_path, monkeypatch):
    monkeypatch.delenv(V.MASTER_KEY_ENV, raising=False)
    monkeypatch.setitem(R.DEFAULTS, "vault_path", str(tmp_path / "vault.enc"))
    monkeypatch.setitem(
        R.DEFAULTS, "master_keyfile", str(tmp_path / ".master_key")
    )
    R.reset_config_cache()
    R.reset_vault()
    yield
    R.reset_config_cache()
    R.reset_vault()


# --- api handlers ------------------------------------------------------------

def test_secret_set_roundtrip_masked_echo(tmp_vault):
    out = run(
        secret_set.SecretSet().process(
            {"name": "MY_KEY", "value": "sk-live-abcdef", "scopes": ["tool_a"]},
            None,
        )
    )
    assert out["ok"] is True
    assert out["data"]["name"] == "MY_KEY"
    assert out["data"]["scopes"] == ["tool_a"]
    assert out["data"]["masked"] == V.mask_value("sk-live-abcdef")
    # the raw value never appears in the response
    assert "sk-live-abcdef" not in json.dumps(out)
    # but it landed in the vault, decryptable in-process
    assert R.get_vault().get("MY_KEY") == "sk-live-abcdef"


def test_secret_set_rejects_non_dict_body(tmp_vault):
    out = run(secret_set.SecretSet().process(["not", "a", "dict"], None))
    assert out["ok"] is False
    out = run(secret_delete.SecretDelete().process("x", None))
    assert out["ok"] is False
    out = run(secret_list.SecretList().process(5, None))
    assert out["ok"] is False


def test_secret_set_missing_and_invalid(tmp_vault):
    out = run(secret_set.SecretSet().process({"name": "K"}, None))
    assert out == {"ok": False, "error": "value required"}
    # invalid name → FileVault raises ValueError → clean ok:false, not a 500
    out = run(
        secret_set.SecretSet().process(
            {"name": "bad\nname", "value": "v-12345678"}, None
        )
    )
    assert out["ok"] is False
    assert "invalid secret name" in out["error"]
    # non-iterable scopes must not crash the handler
    out = run(
        secret_set.SecretSet().process(
            {"name": "OK_NAME", "value": "v-12345678", "scopes": 5}, None
        )
    )
    assert out["ok"] is True
    assert out["data"]["scopes"] == []


def test_secret_set_accepts_comma_scopes(tmp_vault):
    out = run(
        secret_set.SecretSet().process(
            {"name": "K2", "value": "v-12345678", "scopes": "a, b ,, "}, None
        )
    )
    assert out["ok"] is True
    assert out["data"]["scopes"] == ["a", "b"]


def test_secret_delete(tmp_vault):
    R.get_vault().set("GONE", "v-12345678")
    assert run(secret_delete.SecretDelete().process({"name": "GONE"}, None))[
        "ok"
    ] is True
    assert R.get_vault().get("GONE") is None
    out = run(secret_delete.SecretDelete().process({"name": "GONE"}, None))
    assert out["ok"] is False


def test_secret_list_returns_meta_only(tmp_vault):
    R.get_vault().set("A_KEY", "secret-value-12345", ["s1"])
    out = run(secret_list.SecretList().process({}, None))
    assert out["ok"] is True
    assert out["data"] == [{"name": "A_KEY", "scopes": ["s1"]}]
    assert "secret-value-12345" not in json.dumps(out)


def test_missing_vault_reads_mint_no_keyfile(tmp_path, monkeypatch):
    """Read-only paths on a vault-less install must not create .master_key."""
    monkeypatch.delenv(V.MASTER_KEY_ENV, raising=False)
    monkeypatch.setitem(R.DEFAULTS, "vault_path", str(tmp_path / "vault.enc"))
    monkeypatch.setitem(
        R.DEFAULTS, "master_keyfile", str(tmp_path / ".master_key")
    )
    R.reset_config_cache()
    R.reset_vault()
    try:
        assert run(secret_list.SecretList().process({}, None)) == {
            "ok": True,
            "data": [],
        }
        assert (
            run(secret_delete.SecretDelete().process({"name": "X"}, None))["ok"]
            is False
        )
        assert not (tmp_path / ".master_key").exists()
    finally:
        R.reset_config_cache()
        R.reset_vault()


def test_handlers_do_not_override_framework_auth():
    """Handlers must inherit ApiHandler's auth/CSRF/methods — the invariant is
    'no override', not the stub's values (which could drift from runtime)."""
    for cls in (
        secret_set.SecretSet,
        secret_delete.SecretDelete,
        secret_list.SecretList,
    ):
        for attr in (
            "requires_auth",
            "requires_csrf",
            "requires_api_key",
            "requires_loopback",
            "get_methods",
        ):
            assert attr not in cls.__dict__


# --- module CLI --------------------------------------------------------------

def _cli_args(vpath, *rest):
    return ["--vault-path", str(vpath), "--env-var", "TEST_VAULT_KEY", *rest]


def _stdin(monkeypatch, text):
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_cli_add_list_delete(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TEST_VAULT_KEY", "test-master")
    vpath = tmp_path / "vault.enc"
    _stdin(monkeypatch, "cli-secret-99\n")
    assert V.main(_cli_args(vpath, "add", "CLI_KEY")) == 0
    out = capsys.readouterr().out
    assert "cli-secret-99" not in out
    assert "CLI_KEY" in out and "••••••••" in out

    assert V.main(_cli_args(vpath, "list")) == 0
    assert "CLI_KEY" in capsys.readouterr().out

    assert V.main(_cli_args(vpath, "delete", "CLI_KEY")) == 0
    assert V.main(_cli_args(vpath, "delete", "CLI_KEY")) == 1


def test_cli_add_empty_stdin_fails_clean(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TEST_VAULT_KEY", "test-master")
    _stdin(monkeypatch, "")
    assert V.main(_cli_args(tmp_path / "v.enc", "add", "K")) == 2
    assert "empty secret value" in capsys.readouterr().err


def test_cli_add_rejects_bad_name_without_minting_key(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_VAULT_KEY", "test-master")
    _stdin(monkeypatch, "v-12345678\n")
    vpath = tmp_path / "vault.enc"
    assert V.main(_cli_args(vpath, "add", "bad name")) == 2
    assert not vpath.exists()
    assert not (tmp_path / ".master_key").exists()


def test_cli_add_refuses_to_mint_key_for_existing_vault(tmp_path, monkeypatch):
    """Existing vault + no keyfile + no env → refuse, don't strand records."""
    vpath = tmp_path / "vault.enc"
    V.FileVault(str(vpath), master_key="original").set("K", "v-12345678")
    # CLI env has no TEST_VAULT_KEY and no keyfile beside the vault
    monkeypatch.delenv("TEST_VAULT_KEY", raising=False)
    _stdin(monkeypatch, "anything\n")
    assert V.main(_cli_args(vpath, "add", "NEW")) == 2


def test_cli_read_cmds_on_missing_vault_mint_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_VAULT_KEY", "test-master")
    missing = tmp_path / "nope.enc"
    assert V.main(_cli_args(missing, "list")) == 0
    assert V.main(_cli_args(missing, "delete", "K")) == 1
    assert not (tmp_path / ".master_key").exists()


def test_cli_vault_file_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_VAULT_KEY", "test-master")
    vpath = tmp_path / "vault.enc"
    _stdin(monkeypatch, "v-12345678\n")
    V.main(_cli_args(vpath, "add", "K"))
    if os.name != "nt":
        assert oct(vpath.stat().st_mode & 0o777) == "0o600"
        keyfile = tmp_path / ".master_key"
        # no keyfile here — the env var carried the key
        assert not keyfile.exists()


def test_cli_keyfile_created_0600_atomically(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_VAULT_KEY", raising=False)
    monkeypatch.delenv(V.MASTER_KEY_ENV, raising=False)
    vpath = tmp_path / "vault.enc"
    _stdin(monkeypatch, "v-12345678\n")
    assert V.main(_cli_args(vpath, "add", "K")) == 0
    keyfile = tmp_path / ".master_key"
    assert keyfile.is_file()
    if os.name != "nt":
        assert oct(keyfile.stat().st_mode & 0o777) == "0o600"
