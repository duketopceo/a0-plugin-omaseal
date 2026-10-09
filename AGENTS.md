# a0-plugin-omaseal — agent notes

An [Agent Zero](https://github.com/agent0ai/agent-zero) plugin that resolves
secrets by name through a backend chain (OmaSeal CLI → `op` → env → plugin
vault). `README.md` is the user-facing doc; this file is what an agent needs
that the README does not say.

## Commands

```bash
# Tests — standalone, offline, no A0 checkout required
python3.12 -m pytest tests/ -q

# CI (.github/workflows/ci.yml): Python 3.12,
#   python -m pip install pytest cryptography
#   python -m pytest tests/ -q
```

**Use Python 3.12** and a repo-local venv (`.venv/`). `cryptography` is the
only third-party import; A0 already ships it at runtime.

There is no linter or formatter configured. Do not add one in an unrelated
change.

## Layout

| Path | What it is |
|---|---|
| `plugin.yaml` | Manifest — `name: omaseal`. The name is the `usr/plugins/omaseal` install path and the `§§secret()` owner; do not rename casually. |
| `default_config.yaml` | Paths, timeouts, `resolve_order`, templates. **Values of settings are never secrets** — a real key here is a leak. |
| `helpers/vault.py` | AES-256-GCM file vault, ported from Khan's `helpers/khan_vault.py`. Framework-independent: explicit paths, no `helpers.files` import. |
| `helpers/resolve.py` | The chain. `resolve()` raises `ResolutionError` naming tried backends; `resolve_provider_key()` returns `None` instead (the get_api_key hook must not break model calls). |
| `helpers/paths.py` | `get_abs_path` shim — uses the framework helper when present, cwd otherwise. |
| `api/` | `secret_set`, `secret_delete`, `secret_list` — `POST /api/plugins/omaseal/<name>` handlers (`helpers.api.ApiHandler`), auth+CSRF defaults inherited (never overridden). The vault write path lives here; responses echo masked metadata only. The api `secret_list` is vault-metadata-only — narrower than the `secret_list` **tool**, which aggregates the whole chain + backend status. |
| `tools/` | `secret_get`, `secret_list`. Both return masked output only. There is deliberately **no `secret_set` tool** — writes go through `api/secret_set`; a value in tool args lands in chat history. |
| `extensions/python/_functions/models/get_api_key/end/` | Fills `data["result"]` only when dotenv produced nothing. |
| `extensions/python/tool_execute_before/_05_*` | Resolves `§§secret(NAME)` via the chain **before** core `_10_unmask_secrets` (which raises on unknown names). Names present in `secrets.env` are left for core — local file wins. |
| `extensions/python/tool_execute_after/_15_*` | Masks chain-resolved values in `response.message`. |
| `extensions/python/util_model_call_before/_15_*` | Same masking for utility-model `call_data`. |
| `extensions/python/system_prompt/_15_*` | Appends a names-only secrets section when `expose_secret_names` and names exist. |
| `hooks.py` | `install()` probes binary availability into `.omaseal-probe.json`. Never raises. `uninstall()` deliberately keeps `usr/secrets/omaseal/`. |
| `tests/fakebin/` | Fake `omaseal`/`op` CLIs driven by `FAKE_OMASEAL_STORE`/`FAKE_OP_STORE` JSON files. Extend these; never call real CLIs in tests. |

## Conventions that will bite you

- **Imports use the A0-qualified path** — `usr.plugins.omaseal.helpers...`,
  not `helpers.resolve`. `tests/conftest.py` synthesizes the package and
  stubs `helpers.tool`, `helpers.extension`, `helpers.plugins`,
  `helpers.secrets`, and `helpers.api` (ApiHandler + Request/Response names;
  handlers are constructed bare and `process()` is awaited directly — no
  Flask). `helpers.secrets.load_result` is the test knob for
  "a name exists in core `secrets.env`".
- **The mask registry is in-memory** (`resolve.register_value`). Masking
  extensions can only redact values the process has resolved or that live in
  the plugin vault. That is the stated coverage boundary — a secret the
  plugin never touched is core's problem (`secrets.env` masking), not ours.
- **`secret_get` must keep returning masked output.** The value crosses the
  model boundary only inside tool args at execution time.
- **Tests must stay offline** — no real keyring, no `op`, no network.
- Secrets never travel in argv or tool args: `omaseal set` reads stdin; the
  vault write path takes values via the POST body (`api/secret_set`) or
  piped stdin / a TTY prompt (`python -m usr.plugins.omaseal.helpers.vault`
  has no `--value` flag on purpose).


## Code graph index (optional accelerator)

This repo may be indexed by `codebase-memory-mcp` (CBM) on an agent's local
machine — `.codebase-memory/` is gitignored. If your harness exposes CBM
tools (`search_graph`, `trace_path`, `get_architecture`, `detect_changes`),
prefer them for structural questions — symbol lookup, caller/callee traces,
impact analysis — instead of grep/read loops. Reindex after large refactors
(`index_repository`); treat `.codebase-memory/graph.db.zst` as a local cache
artifact, never commit it.
