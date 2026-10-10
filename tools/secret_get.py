import asyncio

from helpers.tool import Tool, Response

from usr.plugins.omaseal.helpers import resolve as R
from usr.plugins.omaseal.helpers.vault import mask_value


class SecretGet(Tool):
    """Check that a secret resolves and return it masked — never the value.

    The value itself never reaches the model. To *use* a secret in a later
    tool call, reference it as §§secret(NAME) in that tool's arguments; the
    unmask extension resolves the placeholder at execution time, in-process.
    """

    async def execute(self, name="", **_kwargs):
        name = (name or "").strip()
        if not name:
            return Response(
                message="secret_get: 'name' is required (a secret name or "
                "'service/account' pair).",
                break_loop=False,
            )
        try:
            resolved = await asyncio.to_thread(R.resolve, name)
        except R.ResolutionError as e:
            return Response(message=f"secret_get: {e}", break_loop=False)
        return Response(
            message=(
                f"secret '{resolved.name}' found via {resolved.source}: "
                f"{mask_value(resolved.value)}\n"
                f"Use it in tool arguments as §§secret({resolved.name}) "
                f"— the placeholder is substituted at execution time and the "
                f"value never appears in chat."
            ),
            break_loop=False,
        )
