"""Mask omaseal-resolved secret values in formatted error messages.

Core `_10_mask_errors` covers secrets.env values only. Errors that echo tool
input or backend output can carry values this plugin resolved from external
backends — the mask registry redacts them here, same policy as the
tool_execute_after and util_model_call_before maskers.
"""

from __future__ import annotations

import asyncio

from helpers.extension import Extension


class OmaSealMaskErrors(Extension):
    async def execute(self, **kwargs):
        if not self.agent:
            return
        msg = kwargs.get("msg")
        if not isinstance(msg, dict) or not isinstance(msg.get("message"), str):
            return
        from usr.plugins.omaseal.helpers import resolve as R

        msg["message"] = await asyncio.to_thread(R.mask_text, msg["message"])
