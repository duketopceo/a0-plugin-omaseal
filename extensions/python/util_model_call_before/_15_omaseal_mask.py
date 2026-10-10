"""Mask omaseal-resolved secret values in utility-model call input.

Core masks secrets.env values; this covers the values this plugin resolved
from external backends so they never leave the process in a utility prompt.
"""

from __future__ import annotations

import asyncio

from helpers.extension import Extension


class OmaSealMaskUtilCall(Extension):
    async def execute(self, **kwargs):
        if not self.agent:
            return
        call_data: dict = kwargs.get("call_data", {})
        if not call_data:
            return
        from usr.plugins.omaseal.helpers import resolve as R

        if system := call_data.get("system"):
            call_data["system"] = await asyncio.to_thread(R.mask_text, system)
        if message := call_data.get("message"):
            call_data["message"] = await asyncio.to_thread(R.mask_text, message)
