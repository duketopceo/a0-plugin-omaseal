"""POST /api/plugins/omaseal/secret_list — vault metadata (names + scopes only)."""

from __future__ import annotations

from helpers.api import ApiHandler, Request

from usr.plugins.omaseal.helpers import resolve


class SecretList(ApiHandler):
    async def process(self, input: dict, request: Request) -> dict:
        if not isinstance(input, dict):
            return {"ok": False, "error": "object body required"}
        v = resolve.get_vault_if_exists()
        return {"ok": True, "data": v.list_meta() if v else []}
