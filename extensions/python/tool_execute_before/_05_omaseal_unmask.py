"""Resolve §§secret(NAME) placeholders via the omaseal chain before core
unmasking runs.

Core `_10_unmask_secrets` raises RepairableException on placeholders that are
not in secrets.env. This extension runs first (lower prefix) and substitutes
any placeholder the omaseal chain can resolve; names already defined in
secrets.env are left for core, preserving the local file's precedence. Names
that resolve nowhere still reach core and produce its normal error.
"""

from __future__ import annotations

import re

from helpers.extension import Extension

PLACEHOLDER_PATTERN = re.compile(r"§§secret\(([^)]+)\)")


class OmaSealUnmask(Extension):
    async def execute(self, **kwargs):
        if not self.agent:
            return
        tool_args = kwargs.get("tool_args")
        if not tool_args:
            return

        from usr.plugins.omaseal.helpers import resolve as R

        core_secrets = _core_secret_names()

        def subst(value):
            if not isinstance(value, str) or "§§secret(" not in value:
                return value

            def repl(match):
                name = match.group(1).strip()
                if name.upper() in core_secrets:
                    return match.group(0)  # core handles it
                try:
                    return R.resolve(name).value
                except Exception:
                    return match.group(0)  # leave for core's error path

            return PLACEHOLDER_PATTERN.sub(repl, value)

        for k, v in tool_args.items():
            tool_args[k] = subst(v)


def _core_secret_names() -> set[str]:
    """Names already covered by the core secrets store (secrets.env et al.).
    Empty set on any failure — the chain then takes first shot at every
    placeholder."""
    try:
        from helpers.secrets import get_secrets_manager

        return {k.upper() for k in get_secrets_manager().load_secrets().keys()}
    except Exception:
        return set()
