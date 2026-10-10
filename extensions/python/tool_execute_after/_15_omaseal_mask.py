"""Mask omaseal-resolved secret values in tool output.

Runs after core's secrets.env masking and covers the values this plugin
resolved (keyring, op, env fallback, vault) plus every value in the plugin
vault. Values shorter than mask_min_length are skipped — same policy as core.
"""

from __future__ import annotations

import asyncio

from helpers.extension import Extension
from helpers.tool import Response


class OmaSealMaskToolOutput(Extension):
    async def execute(self, response: Response | None = None, **kwargs):
        del kwargs
        if not self.agent or not response:
            return
        from usr.plugins.omaseal.helpers import resolve as R

        if isinstance(response.message, str):
            response.message = await asyncio.to_thread(
                R.mask_text, response.message
            )
