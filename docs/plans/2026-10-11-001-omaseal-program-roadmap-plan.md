---
title: "a0-plugin-omaseal program roadmap"
type: program-roadmap
status: proposed
date: 2026-10-11
origin: docs/research/2026-10-11-landscape.md
---

# a0-plugin-omaseal program roadmap

> Written by hand in the shape of the sibling program plans. `compound-engineering:ce-plan` was not run: the scope is docs only and the repo is small. Claims checked against the code on 2026-10-11.

## Summary

Keep it small and security-first. The gap users hit first is that a stock install has a vault with no way to fill it from the UI. Everything else is trimming and hardening.

## Now / Next / Later

| ID | Unit | Horizon | Difficulty |
|---|---|---|---|
| U1 | Pin CI actions by SHA, add `permissions: contents: read` | Now | easy |
| U2 | Delete the unused `omaseal_socket` setting | Now | easy |
| U3 | `omaseal_status` token-free API (backends live, names count) | Next | easy |
| U4 | Settings panel: backend status chips and a vault write form | Next | medium |
| U5 | Plugin Hub listing | Next | easy |
| U6 | Proxy mode for HTTP tools (placeholder swapped at the network edge) | Later | hard |

## Units

### U1. CI hardening
- Status: Now. Evidence: `.github/workflows/ci.yml` uses `actions/checkout@v4` and `setup-python@v5` tags and has no `permissions:` block; sibling repos pin SHAs.
- Verification: workflow runs green on a PR. **Difficulty**: easy. **Feasibility**: none blocking; public repo so hosted CI runs.
- **Simpler alternative**: none; it is a three-line change.

### U2. Delete `omaseal_socket`
- Status: Now. Evidence: `default_config.yaml` line 11 declares it "reserved for future IPC transport"; `grep` finds no reader in any `.py`.
- Verification: tests pass; `get_config()` merge still works for users who set it. **Difficulty**: easy.
- **Feasibility**: a user config containing the key must not error (config is merged, so it should be ignored; add a test).
- **Simpler alternative**: this unit is the simplification.

### U3. `omaseal_status` API
- Status: Next. Evidence: `resolve.backend_status()` already returns the booleans and is used by the system-prompt extension and `secret_list`.
- Dependencies: none. Verification: a test beside `tests/test_api_write.py`. Returns booleans and counts only, never names' values.
- **Difficulty**: easy. **Feasibility**: names are already shown to the agent when `expose_secret_names` is true; the API must honour that flag.
- **Simpler alternative**: let the panel call the existing api `secret_list` and derive status from its metadata.

### U4. Settings panel with vault write form
- Status: Next. Evidence: there is no `webui/` directory; the vault write path (`api/secret_set`, `secret_delete`, `secret_list`) is API-only.
- Dependencies: U3. Verification: manual test in a live Agent Zero (never done on this machine so far); API tests already cover the routes.
- **Difficulty**: medium. The form posts a value over a CSRF-protected route; it must never echo or store the value client-side.
- **Feasibility**: depends on Agent Zero's panel conventions (`settings_sections: external`, `x-data` Alpine). A value typed into a browser form is out of the model's reach, which preserves the "no secret in chat" rule.
- **Simpler alternative**: skip the form. The shell path (`python -m usr.plugins.omaseal.helpers.vault add`, stdin or TTY prompt) is already in the README, so the form is convenience for users without shell access to the container.

### U5. Plugin Hub listing
- Status: Next. Evidence: `a0-openrouter-spend/index/omaseal` is staged; Hub status is "pending". Add a Patchbay thumbnail when resubmitting (square, 20 KB or less; [a0-plugins](https://github.com/agent0ai/a0-plugins)).
- **Difficulty**: easy. **Feasibility**: maintainer review time. **Simpler alternative**: git-clone install only.

### U6. Proxy mode
- Status: Later. Evidence: research table; Infisical's proxy keeps the credential out of the agent process.
- **Difficulty**: hard. A forward proxy, per-host allow rules, and a story for non-HTTP tools.
- **Feasibility**: Agent Zero tools are in-process Python; most secret use is HTTP headers, so it is plausible but a new component.
- **Simpler alternative**: keep placeholder substitution plus masking, which is the current model, and document the boundary.

## Verdict

Standalone, no merge or retirement. The only deletion available is U2 (one config key).
