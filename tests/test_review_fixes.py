"""Regression tests for the high-agent review fix round (Khan Caravanserai).

Covers: _run stdout stripping, vault 'secrets'-key KeyError, scope
enforcement wiring, the uncoreable-placeholder guard, post-execute arg
remask, and the verbatim secret_get hint.
"""

import asyncio
import json
import os
import stat
import sys

import pytest

import helpers.errors
from usr.plugins.omaseal.helpers import resolve as R

FAKEBIN = os.path.join(os.path.dirname(__file__), "fakebin")
SECRET = "sk-or-chain-resolved-42"


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
    for var in ("OPENROUTER_API_KEY", "BROWSER_ONLY_KEY", "MY_ONLY_KEY"):
        monkeypatch.delenv(var, raising=False)
    R.reset_config_cache()
    R.reset_vault()
    yield tmp_path
    R.reset_config_cache()
    R.reset_vault()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Loop:
    current_tool = None


class _Agent:
    context = None
    loop_data = _Loop()


# --- _run stdout stripping -----------------------------------------------------

def test_run_returns_stripped_stdout(env):
    out = R._run([sys.executable, "-c", "print('  padded-value-42  ')"], 5.0)
    assert out == "padded-value-42"


def test_resolved_value_has_no_trailing_newline(env):
    resolved = R.resolve("openrouter/api_key")
    assert resolved.value == SECRET
    assert "\n" not in resolved.value


# --- vault corrupt-path coverage ------------------------------------------------

def test_vault_missing_secrets_key_marks_corrupt(env):
    vpath = R.get_config()["vault_path"]
    os.makedirs(os.path.dirname(vpath), exist_ok=True)
    with open(vpath, "w", encoding="utf-8") as f:
        f.write('{"version": 1}')  # valid JSON, no "secrets" key
    v = R.get_vault()
    assert v._corrupt
    with pytest.raises(ValueError, match="unreadable"):
        v.set("X_KEY", "value-00000001", [])
    # resolution path must not crash — corrupt vault just resolves nothing
    with pytest.raises(R.ResolutionError):
        R.resolve("any/name")


# --- scope enforcement ------------------------------------------------------------

def test_vault_scope_enforcement(env):
    v = R.get_vault()
    v.set("SCOPED_KEY", "scoped-value-00000001", ["web_fetch"])
    # unscoped in-process caller resolves permissively
    assert v.get("SCOPED_KEY") == "scoped-value-00000001"
    # wrong scope denied
    with pytest.raises(PermissionError):
        v.get("SCOPED_KEY", requester_scope="code_execution")
    # matching scope resolves
    assert v.get("SCOPED_KEY", requester_scope="web_fetch") == (
        "scoped-value-00000001"
    )
    # scope-less record resolves for any named requester
    v.set("PLAIN_KEY", "plain-value-00000001", [])
    assert v.get("PLAIN_KEY", requester_scope="anything") == (
        "plain-value-00000001"
    )


def test_scoped_values_still_masked(env):
    """Scope enforcement must not thin the mask registry."""
    from usr.plugins.omaseal.helpers import vault as V

    v = R.get_vault()
    v.set("SCOPED_KEY", "scoped-value-00000001", ["web_fetch"])
    vals = v.all_secret_values()
    assert "scoped-value-00000001" in vals
    out = V.redact_values("echo scoped-value-00000001", vals)
    assert "scoped-value-00000001" not in out


def test_unmask_denies_scoped_secret_for_other_tool(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )

    R.get_vault().set("browser.only/key", "browser-secret-00000042",
                      ["browser_use"])
    args = {"k": "x=§§secret(browser.only/key)"}
    with pytest.raises(helpers.errors.RepairableException):
        run(OmaSealUnmask(agent=_Agent()).execute(
            tool_args=args, tool_name="code_execution"))


def test_unmask_scope_allows_matching_tool(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )

    R.get_vault().set("browser.only/key", "browser-secret-00000042",
                      ["browser_use"])
    args = {"k": "x=§§secret(browser.only/key)"}
    run(OmaSealUnmask(agent=_Agent()).execute(
        tool_args=args, tool_name="browser_use"))
    assert args["k"] == "x=browser-secret-00000042"


# --- uncoreable-placeholder guard -------------------------------------------------

def test_unmask_raises_on_slash_name_leftover(env):
    """§§secret(svc/acct) is invisible to core's ALIAS_PATTERN — a failed
    resolution would pass the literal placeholder to the tool silently."""
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )

    args = {"k": "curl -H §§secret(no.such/name)"}
    with pytest.raises(helpers.errors.RepairableException,
                       match="no.such/name"):
        run(OmaSealUnmask(agent=_Agent()).execute(
            tool_args=args, tool_name="code_execution"))
    assert args["k"] == "curl -H §§secret(no.such/name)"  # untouched


def test_unmask_core_pattern_leftover_left_for_core(env):
    """Core-parseable names still reach core's own error path."""
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )

    args = {"k": "§§secret(NOPE_NOWHERE)"}
    run(OmaSealUnmask(agent=_Agent()).execute(
        tool_args=args, tool_name="t"))
    assert args["k"] == "§§secret(NOPE_NOWHERE)"


# --- remask ----------------------------------------------------------------------

def test_remask_restores_placeholders(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_before._05_omaseal_unmask import (  # noqa: E501
        OmaSealUnmask,
    )
    from usr.plugins.omaseal.extensions.python.tool_execute_after._20_omaseal_remask import (  # noqa: E501
        OmaSealRemaskArgs,
    )

    agent = _Agent()

    class _Tool:
        pass

    tool = _Tool()
    agent.loop_data.current_tool = tool
    args = {"k": f"Bearer §§secret(openrouter/api_key)"}
    tool.args = args

    run(OmaSealUnmask(agent=agent).execute(
        tool_args=args, tool_name="code_execution"))
    assert args["k"] == f"Bearer {SECRET}"
    assert tool._omaseal_remask

    run(OmaSealRemaskArgs(agent=agent).execute())
    assert args["k"] == "Bearer §§secret(openrouter/api_key)"
    assert not hasattr(tool, "_omaseal_remask")


def test_remask_noop_without_record(env):
    from usr.plugins.omaseal.extensions.python.tool_execute_after._20_omaseal_remask import (  # noqa: E501
        OmaSealRemaskArgs,
    )

    agent = _Agent()
    run(OmaSealRemaskArgs(agent=agent).execute())  # no current_tool — no crash


# --- error_format mask ------------------------------------------------------------

def test_error_message_masked(env):
    from usr.plugins.omaseal.extensions.python.error_format._15_omaseal_mask import (  # noqa: E501
        OmaSealMaskErrors,
    )

    R.resolve("openrouter/api_key")  # registers value
    msg = {"message": f"tool failed with {SECRET} oh no"}
    run(OmaSealMaskErrors(agent=_Agent()).execute(msg=msg))
    assert SECRET not in msg["message"]
    assert "***REDACTED***" in msg["message"]


# --- secret_get verbatim hint ------------------------------------------------------

def test_secret_get_hint_uses_verbatim_name(env):
    from usr.plugins.omaseal.tools.secret_get import SecretGet

    resp = run(SecretGet(agent=None).execute(name="openrouter/api_key"))
    assert "§§secret(openrouter/api_key)" in resp.message
    assert "OPENROUTER" not in resp.message
