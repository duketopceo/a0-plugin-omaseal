"""Inject available secret NAMES into the system prompt — never values.

Gives the agent awareness of which credentials exist on this host so it can
use §§secret(NAME) placeholders and the secret_get/secret_list tools without
guessing. Disable with `expose_secret_names: false` in plugin settings.
"""

from __future__ import annotations

import asyncio
from typing import Any

from helpers.extension import Extension


class OmaSealSecretsPrompt(Extension):
    async def execute(self, system_prompt: list = [], **kwargs: Any):
        del kwargs
        if not self.agent:
            return
        try:
            from usr.plugins.omaseal.helpers import resolve as R

            cfg = await asyncio.to_thread(R.get_config)
            if not cfg["expose_secret_names"]:
                return
            names = await asyncio.to_thread(R.list_secret_names)
            if not names:
                return
            status = await asyncio.to_thread(R.backend_status)
            live = ", ".join(k for k, v in status.items() if v) or "none"
            listing = "\n".join(f"- {n}" for n in names)
            system_prompt.append(
                "## Secrets (via omaseal plugin)\n"
                "These secrets are available on this host — names only, "
                "values are never shown:\n"
                f"{listing}\n\n"
                f"Live backends: {live}\n"
                "To use a secret, write §§secret(NAME) in tool arguments; it "
                "is substituted at execution time. Check availability with "
                "secret_get / secret_list. Never ask the user to paste a "
                "secret into chat."
            )
        except Exception:
            return
