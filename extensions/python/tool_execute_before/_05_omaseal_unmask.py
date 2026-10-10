"""Resolve §§secret(NAME) placeholders via the omaseal chain before core
unmasking runs.

Core `_10_unmask_secrets` raises RepairableException on placeholders that are
not in secrets.env. This extension runs first (lower prefix) and substitutes
any placeholder the omaseal chain can resolve; names already defined in
secrets.env are left for core, preserving the local file's precedence.

Failure surface: placeholders whose names core's ALIAS_PATTERN cannot match
(`service/account`, `name.with.dots`, digit-leading) would pass through to
the tool as literal text — core never sees them. We raise RepairableException
for those ourselves so a failed resolution can never leak a raw placeholder
into a command line or request body.

Resolution runs in a worker thread: the chain shells out to CLIs and reads
the vault — blocking work that has no business on the agent event loop.
"""

from __future__ import annotations

import asyncio
import re

from helpers.extension import Extension
from helpers.errors import RepairableException

PLACEHOLDER_PATTERN = re.compile(r"§§secret\(([^)]+)\)")
# Core helpers.secrets.ALIAS_PATTERN name grammar — what _10_unmask_secrets
# can see and error on itself.
CORE_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_REMAP_ATTR = "_omaseal_remask"


class OmaSealUnmask(Extension):
    async def execute(self, **kwargs):
        if not self.agent:
            return
        tool_args = kwargs.get("tool_args")
        if not tool_args:
            return
        tool_name = str(kwargs.get("tool_name") or "")

        core_secrets = await asyncio.to_thread(_core_secret_names)
        substituted = await asyncio.to_thread(
            _substitute_all, tool_args, core_secrets, tool_name
        )

        remask: dict[str, list[tuple[str, str]]] = {}
        for k, v in tool_args.items():
            new_v, pairs = substituted.get(k, (v, []))
            leftover = _first_uncoreable(new_v)
            if leftover is not None:
                raise RepairableException(
                    f"cannot resolve §§secret({leftover}) in argument '{k}' — "
                    "name is not usable by core secrets and the omaseal chain "
                    "could not resolve it either"
                )
            if pairs:
                tool_args[k] = new_v
                remask[k] = pairs

        # Stash placeholder->value pairs on the live tool so the
        # tool_execute_after remask extension can put placeholders back —
        # tool_args holds raw secrets for the whole post-execute surface
        # (log updates, span close, response plumbing) otherwise.
        if remask:
            tool = getattr(
                getattr(self.agent, "loop_data", None), "current_tool", None
            )
            if tool is not None:
                setattr(tool, _REMAP_ATTR, remask)


def _substitute_all(
    tool_args: dict, core_secrets: set[str], tool_name: str
) -> dict[str, tuple[str, list[tuple[str, str]]]]:
    """Blocking substitution pass, run via asyncio.to_thread. Returns
    {arg_key: (new_value, [(placeholder, resolved_value), ...])} for changed
    args; placeholders that resolve nowhere stay verbatim for core or the
    uncoreable-name guard to reject."""
    from usr.plugins.omaseal.helpers import resolve as R

    out: dict[str, tuple[str, list[tuple[str, str]]]] = {}
    for k, v in tool_args.items():
        if not isinstance(v, str) or "§§secret(" not in v:
            continue
        pairs: list[tuple[str, str]] = []

        def repl(match):
            name = match.group(1).strip()
            if name.upper() in core_secrets:
                return match.group(0)  # core handles it
            try:
                resolved = R.resolve(name, requester_scope=tool_name or None).value
            except Exception:
                return match.group(0)  # leave for core's error path / our guard
            pairs.append((match.group(0), resolved))
            return resolved

        new_v = PLACEHOLDER_PATTERN.sub(repl, v)
        if new_v != v:
            out[k] = (new_v, pairs)
    return out


def _first_uncoreable(value) -> str | None:
    """First leftover §§secret(NAME) whose name core's pattern cannot match —
    those would sail through to the tool as literal text."""
    if not isinstance(value, str) or "§§secret(" not in value:
        return None
    for m in PLACEHOLDER_PATTERN.finditer(value):
        if not CORE_NAME_PATTERN.fullmatch(m.group(1).strip()):
            return m.group(1).strip()
    return None


def _core_secret_names() -> set[str]:
    """Names already covered by the core secrets store (secrets.env et al.).
    Empty set on any failure — the chain then takes first shot at every
    placeholder."""
    try:
        from helpers.secrets import get_secrets_manager

        return {k.upper() for k in get_secrets_manager().load_secrets().keys()}
    except Exception:
        return set()
