"""Restore §§secret(...) placeholders into tool args after execution.

`_05_omaseal_unmask` mutates tool_args in place so the tool sees real
values. The tool's `args` dict is the same object, so raw secrets stay
reachable through `loop_data.current_tool` across the post-execute surface —
log updates, span close, response plumbing — until `current_tool` is cleared
in agent.py's finally. Putting the placeholders back shrinks that window to
the tool's own execute call.

Runs after `_15_omaseal_mask` (output masking first, then arg restore).
"""

from __future__ import annotations

from helpers.extension import Extension

_REMAP_ATTR = "_omaseal_remask"


class OmaSealRemaskArgs(Extension):
    async def execute(self, **kwargs):
        if not self.agent:
            return
        tool = getattr(
            getattr(self.agent, "loop_data", None), "current_tool", None
        )
        remask = getattr(tool, _REMAP_ATTR, None) if tool is not None else None
        if not remask:
            return
        try:
            args = getattr(tool, "args", None) or {}
            for key, pairs in remask.items():
                value = args.get(key)
                if not isinstance(value, str):
                    continue
                for placeholder, raw in pairs:
                    if raw:
                        value = value.replace(raw, placeholder)
                args[key] = value
        finally:
            try:
                delattr(tool, _REMAP_ATTR)
            except AttributeError:
                pass
