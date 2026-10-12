# Landscape: a0-plugin-omaseal (2026-10-11)

Question: how do other tools keep secrets away from an LLM agent, and what does this plugin do that they do not? Code read first (`helpers/resolve.py`, `helpers/vault.py`, `extensions/python/*`, `api/*`); web claims cited, weak sources flagged.

## What this repo is

An Agent Zero plugin that resolves a secret name through a chain (OmaSeal CLI, 1Password `op`, env, plugin vault; `resolve_order`), substitutes `§§secret(NAME)` placeholders at tool execution, masks resolved values in tool output, error text and utility-model calls, and injects provider keys through `models.get_api_key`. It has two tools (`secret_get`, `secret_list`, masked only) and three vault write routes under `api/`. There is deliberately no `secret_set` tool. About 1,350 lines, 81 offline tests, one third-party import (`cryptography`).

## Comparable approaches

| Approach | How it keeps the secret from the agent | Better than this plugin | Worse than this plugin |
|---|---|---|---|
| [Infisical Agent Vault](https://infisical.com/docs/documentation/getting-started/choose-a-product/agent-vault) | Agent calls out through a proxy that attaches the real credential at the network boundary; the agent never holds it. The [platform page](https://infisical.com/ai/platform/secrets-management) describes a placeholder swap via `HTTPS_PROXY`; one review says the product is preview ([source](https://computingforgeeks.com/ai-agent-secrets-management-infisical/), unverified) | Stronger: a leaked prompt cannot contain the value because the agent process never sees it | Needs a proxy and a server; works for HTTP calls only, not for secrets used in a local command |
| 1Password CLI and MCP | Runtime injection: `op read op://vault/item/field`; a vendor-adjacent [comparison](https://www.stork.ai/alternatives/1password) says an MCP server and agentic autofill avoid exposing secrets to the model (unverified) | Mature vault, audit, sharing | No agent-side placeholder or output masking found in the sources I read; this plugin calls `op read` as one backend |
| Doppler | MCP server, scoped machine identities, JIT injection per a [comparison](https://fast.io/resources/best-secret-management-tools-ai-agents/) (vendor-adjacent) | Team workflows, rotation | Hosted service; no masking detail found |
| Agent Zero core (`secrets.env`, `§§secret()`) | Placeholder substitution and masking for names in `usr/secrets.env` | Built in | One flat file; no keyring, no 1Password, no encrypted store. This plugin layers on it and leaves names in `secrets.env` to core |
| [OmaSeal](https://github.com/duketopceo/OmaSeal) (the keyring) | Gnome-keyring backed service/account store with an MCP server for external agents | Native to the desktop | Only on Linux with a Secret Service; this plugin works without it |

## What users expect

- The agent can use a secret without reading it. Every source above converges on "real secrets live in the vault, agents hold placeholders" (see the [fast.io roundup](https://www.fast.io/resources/best-secret-management-tools-ai-agents.md)).
- One interface across backends, with clear precedence.
- No secret value ever in chat history, which is why a write tool is absent here.

## What is unique here

1. A fallback chain that also works on a stock Agent Zero container: the encrypted vault needs no external service.
2. Masking in three places: tool output, `error_format`, and utility-model `call_data`.
3. Tiny, auditable, offline-testable (fake `omaseal` and `op` binaries in `tests/fakebin/`).

## Gaps and risks

- The mask registry is in memory: it only redacts values the process has resolved or that sit in the plugin vault (AGENTS.md states this boundary).
- No UI for the vault: writes go through `api/secret_set` only, so a stock-install user has no way to add a secret without a raw HTTP call.
- A reserved setting, `omaseal_socket`, is unused anywhere in the code.
- CI workflow uses floating `@v4` / `@v5` action tags and no `permissions:` block, unlike sibling repos.
- Placeholder substitution still hands the real value to the tool process; a proxy model (Infisical) would not.
