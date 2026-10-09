# Backend setup per platform

The plugin resolves secrets through `resolve_order` (default: `omaseal` →
`op` → `env` → `vault`). This page covers getting each backend live.

## omaseal (gnome-keyring)

Linux desktops with a Secret Service keyring — the primary target is Omarchy
(Arch). Install and store:

```bash
yay -S omaseal
omaseal set openrouter api_key   # reads the secret from stdin
```

The plugin calls `omaseal get` then `omaseal resolve`; the latter also walks
OmaSeal's own 1Password/Bitwarden fallback. Requires `omaseal` on `PATH` or
`omaseal_bin` set to the binary path.

## op (1Password CLI)

Any platform with the `op` binary, including macOS. The plugin runs
`op read <ref>` where `<ref>` comes from `op_reference_template` — default
`op://AgentZero/{service}/{account}`. Create items under an `AgentZero` vault
or adjust the template.

## env

Read from the A0 process environment. `env_name_template` (default `{name}`)
maps the requested name to a variable name; provider keys additionally try
`API_KEY_<SVC>`, `<SVC>_API_KEY`, `<SVC>_API_TOKEN` to match core conventions.

## vault (built-in)

The plugin's AES-256-GCM store at `usr/secrets/omaseal/vault.enc`. Always
available, no external dependency — the fallback that makes the plugin useful
on stock A0, macOS, and Docker. Master key: `OMASEAL_MASTER_KEY` env var, else
`usr/secrets/omaseal/.master_key` (generated on first write, mode 0600).

Write paths (all outside the agent loop — no tool call ever carries a value):

```bash
# Ops shell — works standalone or inside the A0 container via docker exec.
# `add` reads the value from piped stdin or a TTY prompt — never argv.
python -m usr.plugins.omaseal.helpers.vault add OPENROUTER_API_KEY        # TTY prompt
printf %s "$KEY" | python -m usr.plugins.omaseal.helpers.vault add KEY --scope tool_a
python -m usr.plugins.omaseal.helpers.vault list                        # names only
python -m usr.plugins.omaseal.helpers.vault delete OLD_KEY
```

Scopes are stored metadata today — nothing enforces them during resolution
yet (no caller passes `requester_scope`); treat them as labeling until
enforcement lands.

```http
# Authenticated API (CSRF-protected) — the WebUI-facing write path
POST /api/plugins/omaseal/secret_set     {"name": "K", "value": "…", "scopes": ["s"]}
POST /api/plugins/omaseal/secret_delete  {"name": "K"}
POST /api/plugins/omaseal/secret_list    {}   # names + scopes only
```

Vault concurrency contract — `FileVault` is designed for **multiple writers**
(the long-lived A0 process *and* one-shot CLI/API invocations): writes are
`flock`-serialized against a sibling `.lock` file, each instance reloads when
the vault file's mtime changes (so the daemon sees CLI writes and vice versa),
and a corrupt/unreadable vault is read-only until repaired externally — it is
never silently overwritten. Decrypted values are never cached between
operations; do not add a plaintext cache for performance — the port's security
posture deliberately trades it for not retaining secrets in memory.

## Hermes port note

For a Hermes `secret_sources` provider, the portable surface is `FileVault`
(AES-256-GCM, explicit paths, no framework imports) plus the resolve chain's
backend-try logic — both are plain functions in `helpers/vault.py` and
`helpers/resolve.py`. A Hermes plugin would wrap them behind `register(ctx)`
and expose `get(name)`/`list_meta()`; the A0-specific parts (extensions,
tools, api handlers) stay in this repo as the A0 shim.

## Docker caveat

Agent Zero in Docker has no gnome-keyring and no `op` unless you add them to
the image. `env` (container env vars) and `vault` (persisted under the `usr/`
volume) are the legs that work out of the box.

## MCP (external agents only)

`omaseal mcp` serves the same namespace to agents outside A0. This plugin is
in-process and deliberately does not use it.
