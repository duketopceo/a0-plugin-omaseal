# OmaSeal for Agent Zero

One secrets interface for your agent. Store keys once — in the OmaSeal
keyring, 1Password, environment variables, or the plugin's encrypted vault —
and every tool, model call, and plugin resolves them by name. Agents see
secret **names** and masked values only; the real value is substituted at
execution time and masked again on the way out.

Built for the [OmaSeal](https://github.com/duketopceo/OmaSeal) `service /
account` model, but works on stock Agent Zero with no OmaSeal install.

## What you get

- **`secret_list` tool** — available secret names + which backends are live.
- **`secret_get` tool** — confirms a secret resolves, returns it masked
  (`••••••••f456`) with the `§§secret(NAME)` placeholder to reference it by.
- **Provider key injection** — `models.get_api_key()` resolves missing
  provider keys (OpenRouter, Anthropic, …) through the chain at call time.
- **`§§secret(NAME)` unmasking** — placeholders in tool arguments resolve
  through the chain before execution, alongside core's `secrets.env` support.
- **Output masking** — resolved values are redacted from tool output and
  utility-model calls if they ever appear there.
- **System prompt awareness** — injects available secret *names only* so the
  agent knows what it can request (disable via `expose_secret_names`).

## Resolution chain

Configured by `resolve_order` in plugin settings. Default:

1. **`omaseal`** — `omaseal get|resolve <service> <account>` (gnome-keyring on
   Omarchy desktops; also walks OmaSeal's own 1Password/Bitwarden fallback)
2. **`op`** — `op read <op_reference_template>` (1Password CLI)
3. **`env`** — OS environment variable (`env_name_template`)
4. **`vault`** — the plugin's own AES-256-GCM encrypted vault
   (`usr/secrets/omaseal/vault.enc`)

Bare names like `OPENROUTER_API_KEY` resolve as `(service=OPENROUTER_API_KEY,
account=<provider_account>)` on the keyring legs; `service/account` names like
`openrouter/api_key` split explicitly.

## Platform notes

- **Omarchy / Linux desktop:** install OmaSeal (`yay -S omaseal`), store keys
  with `omaseal set <service> <account>`. The plugin picks them up at call
  time — nothing else to configure.
- **macOS:** no gnome-keyring exists — the `omaseal` leg skips cleanly. Use
  `op` (1Password), env vars, or the plugin vault.
- **Docker / headless A0:** same — no keyring in the container. Mount env
  vars, or `exec` into the container and populate the plugin vault. The
  `op` leg works if the `op` binary is in the image.
- **No backends at all:** `secret_get` returns a clear error naming the
  backends tried — never a crash or a silent empty string.

## The vault

The plugin vault is AES-256-GCM encrypted, mode `0600`, master key from
`OMASEAL_MASTER_KEY` or `usr/secrets/omaseal/.master_key` (created on first
write). Populate it from outside the agent — e.g. the `omaseal` CLI or a
small script — not through a tool call, so values never enter chat history.

Uninstalling the plugin does **not** delete `usr/secrets/omaseal/` — stored
secrets survive reinstall on purpose.

## MCP?

OmaSeal ships an MCP server for *external* agents (Claude Code, Cursor, …).
This plugin is in-process Python inside A0, so it calls the CLI directly —
the MCP hop would add a socket dependency and buy nothing. External agents on
the same box should use `omaseal mcp` instead; the secrets namespace is the
same.

## Install

Plugin Hub → Browse → `omaseal`, or copy this repo into
`usr/plugins/omaseal/` and restart Agent Zero.

## Security model

- Secret values are never written to `settings.json`, prompts, chat history,
  logs, or tool output — enforced by tests in `tests/test_security.py`.
- Placeholder substitution happens in-process at tool execution; the model
  only ever writes `§§secret(NAME)`.
- No `secret_set` tool exists: a value in tool arguments would land in chat
  history. Secrets enter the system from outside the agent loop.
- `default_config.yaml` holds paths and policy only, never values.

## License

MIT — see `LICENSE`. Portions adapted from Agent Zero and the Khan fork.
