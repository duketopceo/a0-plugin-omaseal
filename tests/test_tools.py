"""Tool tests — secret_get/secret_list never expose values."""

import asyncio
import json
import os
import stat

import pytest

from usr.plugins.omaseal.helpers import resolve as R
from usr.plugins.omaseal.tools.secret_get import SecretGet
from usr.plugins.omaseal.tools.secret_list import SecretList

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")
SECRET = "sk-or-live-abc123def456"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setitem(R.DEFAULTS, "omaseal_bin",
                       os.path.join(FAKEBIN, "fake_omaseal.py"))
    monkeypatch.setitem(R.DEFAULTS, "op_bin", "/nonexistent/op")
    monkeypatch.setitem(R.DEFAULTS, "vault_path",
                       str(tmp_path / "secrets" / "vault.enc"))
    monkeypatch.setitem(R.DEFAULTS, "master_keyfile",
                       str(tmp_path / "secrets" / ".master_key"))
    os.chmod(os.path.join(FAKEBIN, "fake_omaseal.py"),
             os.stat(os.path.join(FAKEBIN, "fake_omaseal.py")).st_mode
             | stat.S_IXUSR)
    store = tmp_path / "omaseal.json"
    store.write_text(json.dumps({"openrouter/api_key": SECRET,
                                 "stripe/api_key": "sk_live_other_999"}))
    monkeypatch.setenv("FAKE_OMASEAL_STORE", str(store))
    R.reset_config_cache()
    R.reset_vault()
    yield tmp_path
    R.reset_config_cache()
    R.reset_vault()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_secret_get_returns_masked(env):
    tool = SecretGet(agent=None)
    resp = run(tool.execute(name="openrouter/api_key"))
    assert SECRET not in resp.message
    assert "••••••••f456" in resp.message
    assert "omaseal" in resp.message
    assert "§§secret(" in resp.message


def test_secret_get_missing_clear_error(env):
    tool = SecretGet(agent=None)
    resp = run(tool.execute(name="nonexistent/thing"))
    assert "not found" in resp.message
    assert "omaseal" in resp.message  # names the backends tried


def test_secret_get_empty_name(env):
    tool = SecretGet(agent=None)
    resp = run(tool.execute(name=""))
    assert "required" in resp.message


def test_secret_list_names_only(env):
    tool = SecretList(agent=None)
    resp = run(tool.execute())
    assert "openrouter/api_key" in resp.message
    assert "stripe/api_key" in resp.message
    assert SECRET not in resp.message
    assert "sk_live_other_999" not in resp.message
    assert "omaseal" in resp.message  # backend status reported
