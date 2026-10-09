"""POST /api/plugins/omaseal/secret_delete — remove a secret from the vault."""

from __future__ import annotations

from helpers.api import ApiHandler, Request

from usr.plugins.omaseal.helpers import resolve


class SecretDelete(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        if not isinstance(input, dict):
            return {"ok": False, "error": "object body required"}
        name = str(input.get("name") or "").strip()
        if not name:
            return {"ok": False, "error": "name required"}
        v = resolve.get_vault_if_exists()
        if v is None or not v.delete(name):
            return {"ok": False, "error": f"secret '{name}' not found"}
        return {"ok": True, "data": {"name": name}}
