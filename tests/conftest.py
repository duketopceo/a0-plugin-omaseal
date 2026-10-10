"""Make `usr.plugins.omaseal.*` imports resolvable under pytest — the same
qualified path the A0 runtime uses inside usr/plugins/omaseal/ — and stub the
framework modules the plugin imports (helpers.tool, helpers.extension,
helpers.plugins, helpers.secrets) so everything runs standalone, offline.
"""

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pkg(name, path=None):
    mod = types.ModuleType(name)
    mod.__path__ = [str(path)] if path else []
    return mod


_usr = _pkg("usr")
_plugins = _pkg("usr.plugins")
_omaseal = _pkg("usr.plugins.omaseal", ROOT)
_usr.plugins = _plugins
_plugins.omaseal = _omaseal
sys.modules.setdefault("usr", _usr)
sys.modules.setdefault("usr.plugins", _plugins)
sys.modules["usr.plugins.omaseal"] = _omaseal


# --- minimal A0 framework stubs ---------------------------------------------

class Response:
    """Mirrors helpers.tool.Response — a dataclass where break_loop is a
    REQUIRED field. The stub used to default it to False, so a tool that
    forgot the arg passed tests but TypeError'd against the real host."""

    def __init__(self, message, break_loop, additional=None, **kw):
        self.message = message
        self.break_loop = break_loop
        self.additional = additional or {}


class Tool:
    def __init__(self, agent=None, name="", method=None, args=None,
                 message="", loop_data=None, **kw):
        self.agent = agent
        self.name = name
        self.method = method
        self.args = dict(args or {})
        self.message = message
        self.loop_data = loop_data
        self.progress = ""

    def add_progress(self, content):
        if content:
            self.progress += str(content)

    async def execute(self, **kwargs):
        raise NotImplementedError


class Extension:
    def __init__(self, agent=None, **kw):
        self.agent = agent


_helpers = _pkg("helpers")

_tool = types.ModuleType("helpers.tool")
_tool.Tool = Tool
_tool.Response = Response
_helpers.tool = _tool

_ext = types.ModuleType("helpers.extension")
_ext.Extension = Extension
_helpers.extension = _ext

_errors_mod = types.ModuleType("helpers.errors")


class RepairableException(Exception):
    """Stub of helpers.errors.RepairableException — the host class a0
    surfaces to the agent as a tool-fixable error."""


_errors_mod.RepairableException = RepairableException
_helpers.errors = _errors_mod

# Mutable plugin-config stub; tests override by monkeypatching
# usr.plugins.omaseal.helpers.resolve.DEFAULTS then reset_config_cache().
_plugins_mod = types.ModuleType("helpers.plugins")
_plugins_mod.get_plugin_config = lambda name: {}
_helpers.plugins = _plugins_mod

# helpers.secrets is absent by default: simulates "nothing in secrets.env".
# Tests needing a core-secrets name set _secrets_mod.load_result.
_secrets_mod = types.ModuleType("helpers.secrets")
_secrets_mod.load_result = {}


class _SecretsManager:
    def load_secrets(self):
        return dict(_secrets_mod.load_result)


_secrets_mod.get_secrets_manager = lambda context=None: _SecretsManager()
_helpers.secrets = _secrets_mod

# helpers.api: ApiHandler base + Request/Response names the plugin's api/
# handlers import. Handlers are constructed bare and process() is awaited
# directly in tests — no Flask involved.
_api_mod = types.ModuleType("helpers.api")


class ApiHandler:
    def __init__(self, app=None, thread_lock=None):
        self.app = app
        self.thread_lock = thread_lock

    @classmethod
    def requires_auth(cls) -> bool:
        return True

    @classmethod
    def requires_csrf(cls) -> bool:
        return cls.requires_auth()

    @classmethod
    def get_methods(cls):
        return ["POST"]

    async def process(self, input, request):
        raise NotImplementedError


_api_mod.ApiHandler = ApiHandler
_api_mod.Request = object
_api_mod.Response = Response
_helpers.api = _api_mod

sys.modules.setdefault("helpers", _helpers)
sys.modules["helpers.tool"] = _tool
sys.modules["helpers.extension"] = _ext
sys.modules["helpers.errors"] = _errors_mod
sys.modules["helpers.plugins"] = _plugins_mod
sys.modules["helpers.secrets"] = _secrets_mod
sys.modules["helpers.api"] = _api_mod


class FakeAgent:
    def __init__(self, context=None):
        self.context = context


def run(coro):
    """Shared coroutine runner — same convention as the per-file `run`
    helpers in the older test modules (which keep their own copies)."""
    import asyncio

    return asyncio.run(coro)
