import asyncio

from helpers.tool import Tool, Response

from usr.plugins.omaseal.helpers import resolve as R


class SecretList(Tool):
    """List available secret names and which backends are live.

    Names only — never values. Use the names with secret_get or as
    §§secret(NAME) placeholders in tool arguments.
    """

    async def execute(self, **_kwargs):
        names, status = await asyncio.gather(
            asyncio.to_thread(R.list_secret_names),
            asyncio.to_thread(R.backend_status),
        )
        live = [k for k, v in status.items() if v]
        offline = [k for k, v in status.items() if not v]

        lines = ["Available secrets:"]
        if names:
            lines += [f"- {n}" for n in names]
        else:
            lines.append("- (none found)")
        lines.append("")
        lines.append(
            "Backends live: " + (", ".join(live) if live else "none")
        )
        if offline:
            lines.append(
                "Backends unavailable: "
                + ", ".join(offline)
                + " (install the omaseal or op CLI, or populate the plugin "
                "vault, to enable them)"
            )
        lines.append("")
        lines.append(
            "Reference a secret in tool arguments as §§secret(NAME) — the "
            "value is substituted at execution time and never shown."
        )
        return Response(message="\n".join(lines), break_loop=False)
