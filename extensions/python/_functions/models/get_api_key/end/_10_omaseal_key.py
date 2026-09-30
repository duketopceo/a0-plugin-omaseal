"""Resolve provider API keys through the omaseal chain when dotenv has none.

Runs at the end of models.get_api_key(service). Only fires when the
environment produced no key, so existing usr/.env setups are untouched.
The resolved value goes to the model client at call time — it is never
written to settings.json, logged, or shown to the agent. Resolved values are
registered with the plugin's mask registry so masking extensions redact them
if they ever appear in output.
"""

from __future__ import annotations

from helpers.extension import Extension

_MISSING = ("", "none", "null")


class OmaSealApiKey(Extension):
    def execute(self, data: dict | None = None, **kwargs):
        del kwargs
        if not isinstance(data, dict):
            return

        current = str(data.get("result") or "").strip()
        if current.lower() not in _MISSING:
            return

        service = _service_from(data)
        if not service:
            return

        try:
            from usr.plugins.omaseal.helpers import resolve as R

            resolved = R.resolve_provider_key(service)
        except Exception:
            return

        if resolved and resolved.value:
            data["result"] = resolved.value


def _service_from(data: dict) -> str:
    args = data.get("args")
    if isinstance(args, (list, tuple)) and args:
        return str(args[0] or "").strip().lower()
    call_kwargs = data.get("kwargs")
    if isinstance(call_kwargs, dict):
        return str(call_kwargs.get("service") or "").strip().lower()
    return ""
