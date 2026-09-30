"""Resolution chain tests — order, fallthrough, clear errors."""

import json
import os
import stat

import pytest

from usr.plugins.omaseal.helpers import resolve as R

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Per-test config: fresh vault dir, fakebin CLIs, reset caches."""
    vault_path = tmp_path / "secrets" / "vault.enc"
    monkeypatch.setitem(R.DEFAULTS, "omaseal_bin",
                       os.path.join(FAKEBIN, "fake_omaseal.py"))
    monkeypatch.setitem(R.DEFAULTS, "op_bin",
                       os.path.join(FAKEBIN, "fake_op.py"))
    monkeypatch.setitem(R.DEFAULTS, "vault_path", str(vault_path))
    monkeypatch.setitem(R.DEFAULTS, "master_keyfile",
                       str(tmp_path / "secrets" / ".master_key"))
    monkeypatch.setitem(R.DEFAULTS, "resolve_order",
                        ["omaseal", "op", "env", "vault"])
    for b in ("fake_omaseal.py", "fake_op.py"):
        p = os.path.join(FAKEBIN, b)
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    monkeypatch.setenv("FAKE_OMASEAL_STORE", str(tmp_path / "omaseal.json"))
    monkeypatch.setenv("FAKE_OP_STORE", str(tmp_path / "op.json"))
    R.reset_config_cache()
    R.reset_vault()
    yield tmp_path
    R.reset_config_cache()
    R.reset_vault()


def _write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_omaseal_leg_resolves(env):
    _write(env / "omaseal.json", {"openrouter/api_key": "sk-or-from-omaseal-1"})
    r = R.resolve("openrouter/api_key")
    assert r.value == "sk-or-from-omaseal-1"
    assert r.source == "omaseal"


def test_falls_through_to_op(env):
    _write(env / "omaseal.json", {})
    _write(env / "op.json",
           {"op://AgentZero/stripe/api_key": "sk_live_op_1234"})
    r = R.resolve("stripe/api_key")
    assert r.value == "sk_live_op_1234"
    assert r.source == "op"


def test_falls_through_to_env(env, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "env-token-9999")
    r = R.resolve("MY_TOKEN")
    assert r.value == "env-token-9999"
    assert r.source == "env"


def test_falls_through_to_vault(env):
    v = R.get_vault()
    v.set("LOCAL_ONLY", "vault-value-777")
    R.reset_vault()  # force reload from disk path
    r = R.resolve("LOCAL_ONLY")
    assert r.value == "vault-value-777"
    assert r.source == "vault"


def test_no_keyring_gives_clear_error_not_empty(env, monkeypatch):
    # No omaseal store, no op store, no env var, no vault file.
    with pytest.raises(R.ResolutionError) as ei:
        R.resolve("DEFINITELY_MISSING")
    msg = str(ei.value)
    assert "DEFINITELY_MISSING" in msg
    assert "omaseal" in msg and "vault" in msg
    assert msg != ""


def test_resolve_order_config_respected(env, monkeypatch):
    _write(env / "omaseal.json", {"svc/acct": "omaseal-wins-11"})
    monkeypatch.setenv("SVC_ACCT", "env-would-win-22")
    monkeypatch.setitem(R.DEFAULTS, "resolve_order", ["env", "omaseal"])
    R.reset_config_cache()
    r = R.resolve("svc/acct")
    assert r.source == "env"
    assert r.value == "env-would-win-22"


def test_disabled_backend_skipped(env, monkeypatch):
    _write(env / "omaseal.json", {"svc/acct": "should-not-see-1"})
    monkeypatch.setitem(R.DEFAULTS, "resolve_order", ["env", "vault"])
    R.reset_config_cache()
    with pytest.raises(R.ResolutionError):
        R.resolve("svc/acct")


def test_resolve_provider_key_env_spellings(env, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-env-555")
    r = R.resolve_provider_key("openrouter")
    assert r.value == "sk-or-env-555"


def test_resolve_provider_key_via_omaseal(env):
    _write(env / "omaseal.json", {"anthropic/api_key": "sk-ant-omaseal-7"})
    r = R.resolve_provider_key("anthropic")
    assert r.value == "sk-ant-omaseal-7"


def test_resolve_provider_key_missing_returns_none(env):
    assert R.resolve_provider_key("nonexistent-provider") is None


def test_list_secret_names_no_values(env):
    _write(env / "omaseal.json",
           {"openrouter/api_key": "sekret-A", "stripe/key": "sekret-B"})
    v = R.get_vault()
    v.set("VAULTED", "vault-sekret-C")
    names = R.list_secret_names()
    assert "openrouter/api_key" in names
    assert "stripe/key" in names
    assert "VAULTED" in names
    joined = " ".join(names)
    assert "sekret-A" not in joined and "vault-sekret-C" not in joined


def test_backend_status(env):
    status = R.backend_status()
    assert status["omaseal"] is True  # fakebin exists
    assert status["env"] is True
    assert status["vault"] is False   # no vault file yet


def test_missing_binary_leg_skipped(env, monkeypatch):
    monkeypatch.setitem(R.DEFAULTS, "omaseal_bin", "/nonexistent/omaseal")
    R.reset_config_cache()
    monkeypatch.setenv("FALLBACK_OK", "still-works-88")
    r = R.resolve("FALLBACK_OK")
    assert r.value == "still-works-88"
