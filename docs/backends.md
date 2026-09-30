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

Populate it from outside the agent loop:

```python
from usr.plugins.omaseal.helpers.resolve import get_vault
get_vault().set("OPENROUTER_API_KEY", "<value>", ["model_provider"])
```

## Docker caveat

Agent Zero in Docker has no gnome-keyring and no `op` unless you add them to
the image. `env` (container env vars) and `vault` (persisted under the `usr/`
volume) are the legs that work out of the box.

## MCP (external agents only)

`omaseal mcp` serves the same namespace to agents outside A0. This plugin is
in-process and deliberately does not use it.
