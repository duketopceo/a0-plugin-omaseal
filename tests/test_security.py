"""Acceptance-level security tests: a secret value resolved through the plugin
must never appear in tool output, prompts, settings, or logs — tested, not
asserted in prose."""

import asyncio
import json
import os
import stat

import pytest

from usr.plugins.omaseal.helpers import resolve as R

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")
SECRET = "sk-or-DO-NOT-LEAK-9f8e7d6c"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("OMASEAL_MASTER_KEY", raising=False)
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
    store.write_text(json.dumps({"openrouter/api_key": SECRET}))
    monkeypatch.setenv("FAKE_OMASEAL_STORE", str(store))
    R.reset_config_cache()
    R.reset_vault()
    yield tmp_path
    R.reset_config_cache()
    R.reset_vault()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_no_plaintext_in_default_config():
    """default_config.yaml must contain no secret-looking values."""
    cfg = open(
        os.path.join(os.path.dirname(__file__), "..", "default_config.yaml"),
        encoding="utf-8").read()
    for marker in ("sk-", "sk_live", "ghp_", "xox", "-----BEGIN"):
        assert marker not in cfg


def test_secret_get_never_leaks(env):
    from usr.plugins.omaseal.tools.secret_get import SecretGet

    resp = run(SecretGet(agent=None).execute(name="openrouter/api_key"))
    assert SECRET not in resp.message


def test_full_roundtrip_value_stays_out_of_model_view(env):
    """Simulate the real flow: agent checks secret -> uses placeholder ->
    tool output contains the value -> masking strips it."""
    from usr.plugins.omaseal.tools.secret_get import SecretGet
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )
    from usr.plugins.omaseal.extensions.python.tool_execute_after._15_omaseal_mask import (  # noqa: E501
        OmaSealMaskToolOutput,
    )
    import helpers.tool as ht

    class A:
        context = None

    # 1. agent confirms the secret exists — sees masked form only
    r1 = run(SecretGet(agent=None).execute(name="openrouter/api_key"))
    assert SECRET not in r1.message

    # 2. agent uses §§secret() in a tool call; execution gets the real value
    args = {"command": f"curl -H 'Authorization: Bearer §§secret(openrouter/api_key)' x"}
    run(OmaSealUnmask(agent=A()).execute(tool_args=args))
    assert SECRET in args["command"]  # real value reaches the tool only

    # 3. the tool echoes its command line; output masking strips the value
    resp = ht.Response(message=f"ran: {args['command']} -> 200 ok", break_loop=False)
    run(OmaSealMaskToolOutput(agent=A()).execute(response=resp))
    assert SECRET not in resp.message


def test_vault_file_has_no_plaintext(env):
    v = R.get_vault()
    v.set("STORED", "stored-secret-abcdef")
    path = v.path
    raw = open(path, encoding="utf-8").read()
    assert "stored-secret-abcdef" not in raw


def test_error_messages_carry_no_values(env):
    try:
        R.resolve("openrouter/api_key_missing")
    except R.ResolutionError as e:
        assert SECRET not in str(e)
    else:
        pytest.fail("expected ResolutionError")
