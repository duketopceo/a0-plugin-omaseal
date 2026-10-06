"""Secret resolution chain for the omaseal plugin.

Order is configured by ``resolve_order`` in the plugin config (default:
omaseal CLI -> 1Password ``op`` CLI -> environment variable -> plugin vault).

Design rules (from the plugin contract):
- In-process Python talks to the OmaSeal CLI, never the MCP server — MCP is
  for external agents. There is no keyring inside Docker and no gnome-keyring
  on macOS, so every leg degrades cleanly when its binary or backend is
  absent.
- Secret values are never written to settings.json, logs, prompts, or tool
  output. Values we resolve are recorded in an in-memory mask registry so
  masking extensions can redact them if they appear later.
- A name that resolves nowhere produces a clear ResolutionError naming the
  backends that were tried — never a silent empty string.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from usr.plugins.omaseal.helpers import vault as _vault_mod
from usr.plugins.omaseal.helpers.paths import abs_path

DEFAULTS = {
    "omaseal_bin": "",
    "op_bin": "",
    "resolve_order": ["omaseal", "op", "env", "vault"],
    "provider_account": "api_key",
    "op_reference_template": "op://AgentZero/{service}/{account}",
    "env_name_template": "{name}",
    "vault_path": "usr/secrets/omaseal/vault.enc",
    "master_keyfile": "usr/secrets/omaseal/.master_key",
    "master_key_env": "OMASEAL_MASTER_KEY",
    "cli_timeout_s": 10,
    "mask_min_length": 8,
    "expose_secret_names": True,
}


class ResolutionError(Exception):
    """Raised when no backend can supply a requested secret. Message names the
    secret and the backends tried; it never contains a secret value."""


@dataclass
class ResolvedSecret:
    name: str
    value: str
    source: str  # "omaseal" | "op" | "env" | "vault"


# ---------------------------------------------------------------------------
# config

_cfg_lock = threading.Lock()
_cfg_cache: dict | None = None


def get_config() -> dict:
    """Plugin config merged over shipped defaults. Uses A0's
    helpers.plugins.get_plugin_config when the framework is present."""
    global _cfg_cache
    with _cfg_lock:
        if _cfg_cache is not None:
            return _cfg_cache
        cfg = dict(DEFAULTS)
        try:
            from helpers.plugins import get_plugin_config  # type: ignore

            user_cfg = get_plugin_config("omaseal") or {}
            for key, val in user_cfg.items():
                if val is not None:
                    cfg[key] = val
        except Exception:
            pass
        _cfg_cache = cfg
        return cfg


def reset_config_cache() -> None:
    global _cfg_cache
    with _cfg_lock:
        _cfg_cache = None


# ---------------------------------------------------------------------------
# mask registry — values resolved this process, for masking extensions

_mask_lock = threading.Lock()
_known_values: set[str] = set()


def register_value(value: str) -> None:
    if value:
        with _mask_lock:
            _known_values.add(value)


def known_values() -> list[str]:
    with _mask_lock:
        vals = list(_known_values)
    try:
        v = get_vault_if_exists()
        if v is not None:
            vals += v.all_secret_values()
    except Exception:
        pass
    return vals


def mask_text(text: str) -> str:
    if not text:
        return text
    return _vault_mod.redact_values(
        text, known_values(), min_length=int(get_config()["mask_min_length"])
    )


# ---------------------------------------------------------------------------
# CLI backends


def _which(binary: str) -> str | None:
    if not binary:
        return None
    if os.path.sep in binary or binary.startswith("."):
        return binary if Path(binary).is_file() else None
    return shutil.which(binary)


def _run(argv: list[str], timeout: float) -> str | None:
    """Run a secrets CLI. Returns stripped stdout, or None on any failure.
    Never raises; stderr is captured and discarded so an error message can
    never carry a value into our logs."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _split_name(name: str, provider_account: str) -> tuple[str, str]:
    """'service/account' -> (service, account); bare 'name' ->
    (name, provider_account)."""
    name = name.strip()
    if "/" in name:
        service, _, account = name.partition("/")
        return service.strip(), account.strip() or provider_account
    return name, provider_account


def _try_omaseal(service: str, account: str, cfg: dict) -> str | None:
    binary = _which(cfg["omaseal_bin"] or "omaseal")
    if not binary:
        return None
    # `omaseal get` prints the raw secret to stdout; `resolve` additionally
    # walks OmaSeal's own fallback chain (1Password/Bitwarden).
    out = _run([binary, "get", service, account], float(cfg["cli_timeout_s"]))
    if out:
        return out
    return _run([binary, "resolve", service, account], float(cfg["cli_timeout_s"])) or None


def _try_op(service: str, account: str, cfg: dict) -> str | None:
    binary = _which(cfg["op_bin"] or "op")
    if not binary:
        return None
    ref = str(cfg["op_reference_template"]).format(service=service, account=account)
    return _run([binary, "read", ref], float(cfg["cli_timeout_s"]))


def _env_name(name: str, cfg: dict) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
    return str(cfg["env_name_template"]).format(name=normalized)


def _try_env(name: str, cfg: dict) -> str | None:
    return os.environ.get(_env_name(name, cfg)) or None


# ---------------------------------------------------------------------------
# vault backend (lazy — never creates a master key unless the vault is used)

_vault_lock = threading.Lock()
_vault: _vault_mod.FileVault | None = None


def get_vault() -> _vault_mod.FileVault:
    global _vault
    with _vault_lock:
        if _vault is None:
            cfg = get_config()
            path = abs_path(str(cfg["vault_path"]))
            keyfile = abs_path(str(cfg["master_keyfile"]))
            master = _vault_mod.resolve_master_key(
                keyfile, str(cfg["master_key_env"])
            )
            _vault = _vault_mod.FileVault(path, master_key=master)
        return _vault


def reset_vault() -> None:
    global _vault
    with _vault_lock:
        _vault = None


def get_vault_if_exists() -> _vault_mod.FileVault | None:
    """Vault accessor for read-only callers — returns None rather than
    minting a master key when no vault file exists yet."""
    cfg = get_config()
    if not Path(abs_path(str(cfg["vault_path"]))).is_file():
        return None
    return get_vault()


def _try_vault(name: str, cfg: dict) -> str | None:
    path = abs_path(str(cfg["vault_path"]))
    if not Path(path).is_file():
        return None
    try:
        v = get_vault()
        return v.get(name) or _vault_ci_get(v, name)
    except Exception:
        return None


def _vault_ci_get(v: _vault_mod.FileVault, name: str) -> str | None:
    upper = name.upper()
    for meta in v.list_meta():
        if meta["name"].upper() == upper:
            return v.get(meta["name"])
    return None


# ---------------------------------------------------------------------------
# public API

_BACKENDS = {
    "omaseal": lambda name, cfg: _try_omaseal(*_split_name(name, cfg["provider_account"]), cfg),
    "op": lambda name, cfg: _try_op(*_split_name(name, cfg["provider_account"]), cfg),
    "env": lambda name, cfg: _try_env(name, cfg),
    "vault": lambda name, cfg: _try_vault(name, cfg),
}


def resolve(name: str) -> ResolvedSecret:
    """Resolve a secret by name ('service/account' or bare name) through the
    configured chain. Registers the value for masking before returning."""
    cfg = get_config()
    tried: list[str] = []
    for backend in cfg["resolve_order"]:
        fn = _BACKENDS.get(str(backend))
        if fn is None:
            continue
        tried.append(str(backend))
        value = fn(name, cfg)
        if value:
            register_value(value)
            return ResolvedSecret(name=name, value=value, source=str(backend))
    raise ResolutionError(
        f"secret '{name}' not found — tried: {', '.join(tried) or 'no backends configured'}"
    )


def resolve_provider_key(service: str) -> ResolvedSecret | None:
    """Resolve a provider API key for models.get_api_key(). Tries the chain
    under the provider account convention, then common env var spellings the
    env leg would miss (API_KEY_X, X_API_TOKEN). Returns None instead of
    raising so the framework can continue to its own handling."""
    cfg = get_config()
    try:
        return resolve(service)
    except ResolutionError:
        pass
    upper = re.sub(r"[^A-Za-z0-9]", "_", service).upper()
    for env_name in (f"API_KEY_{upper}", f"{upper}_API_KEY", f"{upper}_API_TOKEN"):
        value = os.environ.get(env_name)
        if value:
            register_value(value)
            return ResolvedSecret(name=service, value=value, source="env")
    return None


def list_secret_names() -> list[str]:
    """All discoverable secret names — omaseal service/account pairs, vault
    names, and configured env names. Never returns values."""
    cfg = get_config()
    names: set[str] = set()

    binary = _which(cfg["omaseal_bin"] or "omaseal")
    if binary:
        out = _run([binary, "list", "--json"], float(cfg["cli_timeout_s"]))
        if out:
            try:
                import json

                for item in json.loads(out):
                    svc, acct = item.get("service"), item.get("account")
                    if svc and acct:
                        names.add(f"{svc}/{acct}")
            except Exception:
                pass

    try:
        if Path(abs_path(str(cfg["vault_path"]))).is_file():
            for meta in get_vault().list_meta():
                names.add(meta["name"])
    except Exception:
        pass

    return sorted(names)


def backend_status() -> dict[str, bool]:
    """Which resolution legs are usable right now (binaries present, vault
    file exists, env always on). Used by the settings/banner surface and
    doctor-style reporting."""
    cfg = get_config()
    order = [str(b) for b in cfg["resolve_order"]]
    return {
        "omaseal": "omaseal" in order
        and bool(_which(cfg["omaseal_bin"] or "omaseal")),
        "op": "op" in order and bool(_which(cfg["op_bin"] or "op")),
        "env": "env" in order,
        "vault": "vault" in order
        and Path(abs_path(str(cfg["vault_path"]))).is_file(),
    }
