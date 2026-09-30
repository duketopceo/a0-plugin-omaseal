"""Extension tests — get_api_key injection, unmask-before, mask-after,
util-call masking, names-only system prompt."""

import asyncio
import json
import os
import stat

import pytest

from usr.plugins.omaseal.helpers import resolve as R

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")
SECRET = "sk-or-chain-resolved-42"


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
    store.write_text(json.dumps({"openrouter/api_key": SECRET}))
    monkeypatch.setenv("FAKE_OMASEAL_STORE", str(store))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    R.reset_config_cache()
    R.reset_vault()
    yield tmp_path
    R.reset_config_cache()
    R.reset_vault()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Agent:
    context = None


# --- get_api_key end extension ----------------------------------------------

def test_api_key_filled_from_chain(env):
    from usr.plugins.omaseal.extensions.python._functions.models.get_api_key.end._10_omaseal_key import (  # noqa: E501
        OmaSealApiKey,
    )
    data = {"result": "", "args": ["openrouter"]}
    OmaSealApiKey().execute(data=data)
    assert data["result"] == SECRET


def test_api_key_existing_untouched(env):
    from usr.plugins.omaseal.extensions.python._functions.models.get_api_key.end._10_omaseal_key import (  # noqa: E501
        OmaSealApiKey,
    )
    data = {"result": "existing-key-from-dotenv", "args": ["openrouter"]}
    OmaSealApiKey().execute(data=data)
    assert data["result"] == "existing-key-from-dotenv"


def test_api_key_unknown_service_left_empty(env):
    from usr.plugins.omaseal.extensions.python._functions.models.get_api_key.end._10_omaseal_key import (  # noqa: E501
        OmaSealApiKey,
    )
    data = {"result": "", "args": ["nonexistent"]}
    OmaSealApiKey().execute(data=data)
    assert data["result"] == ""


# --- tool_execute_before unmask ----------------------------------------------

def test_unmask_substitutes_placeholder(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )
    args = {"api_key": "Bearer §§secret(openrouter/api_key)", "url": "x"}
    run(OmaSealUnmask(agent=_Agent()).execute(tool_args=args))
    assert args["api_key"] == f"Bearer {SECRET}"
    assert args["url"] == "x"


def test_unmask_leaves_core_names(env, monkeypatch):
    import helpers.secrets as hs

    hs.load_result = {"LOCAL_NAME": "core-value"}
    try:
        from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
            OmaSealUnmask,
        )
        args = {"k": "§§secret(LOCAL_NAME)"}
        run(OmaSealUnmask(agent=_Agent()).execute(tool_args=args))
        assert args["k"] == "§§secret(LOCAL_NAME)"  # deferred to core
    finally:
        hs.load_result = {}


def test_unmask_unknown_left_for_core_error(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )
    args = {"k": "§§secret(NOPE_NOWHERE)"}
    run(OmaSealUnmask(agent=_Agent()).execute(tool_args=args))
    assert args["k"] == "§§secret(NOPE_NOWHERE)"


# --- masking extensions --------------------------------------------------------

def test_tool_output_masked(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_after._15_omaseal_mask import (  # noqa: E501
        OmaSealMaskToolOutput,
    )
    import helpers.tool as ht

    R.resolve("openrouter/api_key")  # registers value
    resp = ht.Response(message=f"used key {SECRET} ok")
    run(OmaSealMaskToolOutput(agent=_Agent()).execute(response=resp))
    assert SECRET not in resp.message
    assert "***REDACTED***" in resp.message


def test_util_call_masked(env):
    from usr.plugins.omaseal.extensions.python.util_model_call_before._15_omaseal_mask import (  # noqa: E501
        OmaSealMaskUtilCall,
    )
    R.resolve("openrouter/api_key")
    call_data = {"system": f"sys {SECRET}", "message": f"msg {SECRET}"}
    run(OmaSealMaskUtilCall(agent=_Agent()).execute(call_data=call_data))
    assert SECRET not in call_data["system"]
    assert SECRET not in call_data["message"]


# --- system prompt --------------------------------------------------------------

def test_system_prompt_names_only(env):
    from usr.plugins.omaseal.extensions.python.system_prompt._15_omaseal_secrets import (  # noqa: E501
        OmaSealSecretsPrompt,
    )
    prompt: list = []
    run(OmaSealSecretsPrompt(agent=_Agent()).execute(system_prompt=prompt))
    assert len(prompt) == 1
    assert "openrouter/api_key" in prompt[0]
    assert SECRET not in prompt[0]


def test_system_prompt_disabled(env, monkeypatch):
    monkeypatch.setitem(R.DEFAULTS, "expose_secret_names", False)
    R.reset_config_cache()
    from usr.plugins.omaseal.extensions.python.system_prompt._15_omaseal_secrets import (  # noqa: E501
        OmaSealSecretsPrompt,
    )
    prompt: list = []
    run(OmaSealSecretsPrompt(agent=_Agent()).execute(system_prompt=prompt))
    assert prompt == []


def test_system_prompt_empty_when_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setitem(R.DEFAULTS, "omaseal_bin", "/nonexistent/omaseal")
    monkeypatch.setitem(R.DEFAULTS, "vault_path",
                       str(tmp_path / "nope" / "vault.enc"))
    R.reset_config_cache()
    R.reset_vault()
    from usr.plugins.omaseal.extensions.python.system_prompt._15_omaseal_secrets import (  # noqa: E501
        OmaSealSecretsPrompt,
    )
    prompt: list = []
    run(OmaSealSecretsPrompt(agent=_Agent()).execute(system_prompt=prompt))
    assert prompt == []
