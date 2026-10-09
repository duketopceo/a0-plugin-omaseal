"""POST /api/plugins/omaseal/secret_set — write a secret into the plugin vault.

The value travels in the request body only; the response echoes masked
metadata. Auth and CSRF stay at the ApiHandler defaults (on). There is no
secret_set tool on purpose — a value in tool args lands in chat history.
"""

from __future__ import annotations

from helpers.api import ApiHandler, Request

from usr.plugins.omaseal.helpers import resolve, vault


class SecretSet(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        if not isinstance(input, dict):
            return {"ok": False, "error": "object body required"}
        name = str(input.get("name") or "").strip()
        value = input.get("value")
        scopes = vault.parse_scopes(input.get("scopes"))
        if not isinstance(value, str) or not value:
            return {"ok": False, "error": "value required"}
        try:
            resolve.get_vault().set(name, value, scopes)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        return {
            "ok": True,
            "data": {
                "name": name,
                "scopes": scopes,
                "masked": vault.mask_value(value),
            },
        }
