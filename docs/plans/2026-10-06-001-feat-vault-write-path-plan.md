---
title: "Vault write path — close out Khan #192"
date: 2026-10-06
type: feat
source_issue: duketopceo/Khan#192
pipeline: lfg
---

# Vault write path — close out Khan #192

## Context

Khan issue #192: merge `helpers/khan_vault.py` + `khan/secrets.py` into
`a0-plugin-omaseal`. Recon shows the port already landed — `helpers/vault.py`
is the AES-256-GCM file vault (framework-independent), and `helpers/resolve.py`
wires it as the last leg of the chain (`omaseal → op → env → vault`). Masking
extensions, tools (`secret_get`, `secret_list`), and 44 offline tests all exist
and pass.

**What is actually missing:** a write path. `FileVault.set()`/`delete()` exist
but nothing calls them — no `api/`, no CLI, no tool (deliberate: a value in tool
args lands in chat history). Khan's `python -m khan.secrets add|list|delete`
was the write path and does not exist in plugin form. On a stock a0 install
with no host keyring, the vault is currently write-only-from-nothing — the
backend exists but can never hold a secret.

`execute.py` is **not** the right surface: upstream runs it non-interactively
via `api/plugins.py::_run_execute_script` (`sys.executable execute.py`), so a
getpass prompt can never receive input and argv-based values would leak into
process listings.

## Key Technical Decisions

- **KTD-1 (user-approved): Write path via `api/` handlers, never a tool.**
  Rejected alternative: `tools/secret_set.py`. The plugin AGENTS.md already
  forbids it — a value in tool args lands in chat history. API handlers take
  the value in the POST body behind default auth + CSRF and echo back masked
  metadata only.
- **KTD-2 (user-approved): CLI parity via `python -m` on the vault module, not
  `execute.py`.** Rejected alternative: `execute.py` (non-interactive
  subprocess — getpass dead-ends, argv values leak). A `__main__` block on
  `helpers/vault.py` preserves `khan/secrets.py` semantics 1:1:
  `python -m usr.plugins.omaseal.helpers.vault add|list|delete`, `--value` or
  getpass fallback, `--scope` comma-list. `docker exec`-able on stock installs.
- **KTD-3 (user-approved): merge into this repo.** Rejected alternative: a
  standalone `khan_secrets` plugin — would duplicate omaseal's resolve chain.
- **KTD-4 (open → decided in plan): no HashiCorp/1Password stub backends.**
  Khan's stub `VaultBackend`s carry no behavior; `op` is already a live chain
  leg and HashiCorp is out of scope for the plugin's single-box story.

## Implementation Units

### U1. Vault write API handlers

**Goal:** Authenticated, CSRF-protected HTTP write path for the plugin vault.

**Files:**
- `api/__init__.py` (empty — follows `plugins/_a0_connector/api/` precedent)
- `api/secret_set.py`
- `api/secret_delete.py`
- `api/secret_list.py`

**Approach:** Each subclasses `helpers.api.ApiHandler` (from the `helpers`
stubs already used by `tests/conftest.py` / runtime), implements
`async def process(self, input: dict, request: Request) -> dict`. Do not
override `requires_auth`/`requires_csrf` — defaults stay on. Handlers:

- `secret_set`: input `{name, value, scopes?}` → `resolve.get_vault().set(...)`;
  validate non-empty name/value (400-style `{ok: false, error}` on missing);
  on success return `{ok: true, data: {name, scopes, masked: "<masked>"}}` —
  never the value.
- `secret_delete`: input `{name}` → `vault.delete(name)`; `ok:false` when the
  name does not exist.
- `secret_list`: returns `vault.list_meta()` (names + scopes only).
- Register each resolved value via `resolve.register_value` is NOT needed on
  write — `all_secret_values()` already covers vault contents for masking.

### U2. Vault CLI (`__main__` parity)

**Goal:** `python -m usr.plugins.omaseal.helpers.vault add|list|delete`
replaces `python -m khan.secrets`.

**Files:** `helpers/vault.py` (append `main()` + `if __name__ == "__main__"`),
reusing the module's own `FileVault`; paths resolved through
`helpers/paths.py`-style explicit args — CLI takes `--vault-path`,
`--keyfile`, `--env-var` defaults matching `default_config.yaml`
(`usr/secrets/omaseal/vault.enc`, `OMASEAL_MASTER_KEY`, keyfile) so it works
standalone outside a running a0. Deliberately **no** raw-key or `--value`
flag — a master key or secret on argv is a leak.

### U3. Tests

**Files:** `tests/test_api_write.py`, extend `tests/test_vault.py` if needed.

Offline only (conftest already synthesizes `usr.plugins.omaseal` + framework
stubs). Assert: masked echo (value absent from every response field), scope
round-trip via `list_meta`, delete idempotency, missing-field errors, and that
`get()` with a mismatched `requester_scope` raises `PermissionError` unchanged.
CLI: invoke `main()` with `--value` and a tmp `--vault-path`; assert file
created mode-0600 and `list` prints masked names only.

### U4. Docs + version

**Files:** `README.md`, `docs/backends.md`, `plugin.yaml`.

- README: "Writing secrets" section — WebUI/API handlers + `python -m` vault
  CLI + host `omaseal set`/`op item create` paths.
- `docs/backends.md`: vault backend gains a write-path paragraph; add a short
  "Hermes port" note (`register(ctx)` `secret_sources` provider — shared
  `FileVault` + `resolve` logic behind a thin shim).
- `plugin.yaml`: `version: 0.2.0`.

## Verification

```bash
uv run --python 3.12 --with pytest --with cryptography python -m pytest tests/ -q
```

44 existing tests must stay green; new tests cover U1–U2. Grep the diff for
raw-value echo paths (no `value` field returned anywhere). No new third-party
deps.

## Assumptions (headless run — flagged for review)

- Plugin api handlers map filename → `POST /api/plugins/omaseal/<handler>`
  automatically via `helpers.api.register_api_route` (matches
  `_a0_connector` precedent).
- `ApiHandler` default auth/CSRF on is correct for a write surface — verified
  against `helpers/api.py` (`requires_csrf` returns `requires_auth()`).
- `execute.py` deliberately unused (non-interactive invocation).
- Khan-side `helpers/khan_vault.py` remains in the fork until issue #205
  (archive) — this plan does not touch the Khan repo.
