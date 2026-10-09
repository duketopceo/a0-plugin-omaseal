"""Encrypted local vault for the omaseal plugin — ported from Khan's
helpers/khan_vault.py (AES-256-GCM file vault) into a standalone,
framework-independent module.

Differences from the original: no framework imports (paths are explicit or
resolved via helpers.paths), plugin-owned file locations, and the VaultBackend
protocol kept for symmetry with the external resolution chain.

Secrets never appear in list APIs; get() is in-process only.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import hashlib
import json
import os
import re
import secrets as _secrets
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

try:
    import fcntl
except ImportError:  # non-Unix: in-process lock only
    fcntl = None

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DERIVATION_TAG = b"omaseal-vault-v1"


class VaultBackend(Protocol):
    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str, scopes: list[str]) -> None: ...
    def list_meta(self) -> list[dict]: ...
    def delete(self, name: str) -> bool: ...


def _derive_key(master: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        kdf = Scrypt(salt=KEY_DERIVATION_TAG, length=32, n=2**14, r=8, p=1)
        return kdf.derive(master.encode("utf-8"))
    except Exception:
        return hashlib.pbkdf2_hmac(
            "sha256", master.encode("utf-8"), KEY_DERIVATION_TAG, 200_000, dklen=32
        )


MASTER_KEY_ENV = "OMASEAL_MASTER_KEY"
MASTER_KEYFILE_NAME = ".master_key"
MAX_VALUE_BYTES = 64 * 1024

# Names double as §§secret(NAME) placeholders and get echoed into prompts,
# CLI output, and logs — keep them printable and bounded.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")


def parse_scopes(raw: object) -> list[str]:
    """Comma-string or iterable of scope names → stripped, non-empty list.
    Non-iterable inputs (a stray JSON scalar) yield []."""
    if isinstance(raw, str):
        raw = raw.split(",")
    try:
        items = list(raw) if raw is not None else []
    except TypeError:
        return []
    return [s for s in (str(x).strip() for x in items) if s]


def resolve_master_key(keyfile: str, env_var: str) -> str:
    env = os.getenv(env_var)
    if env and env.strip():
        return env.strip()
    path = Path(keyfile)
    if path.is_file():
        key = path.read_text(encoding="utf-8").strip()
        if key:
            return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = _secrets.token_hex(32)
    # O_EXCL create at 0600 — no world-readable window, and a racing writer
    # loses cleanly by re-reading the winner's key instead of minting a split.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC)  # broken empty file — repair
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    return key


@dataclass
class SecretRecord:
    name: str
    scopes: list[str] = field(default_factory=list)
    nonce_b64: str = ""
    ct_b64: str = ""


class FileVault:
    """AES-256-GCM encrypted JSON vault. Never prints values; list_meta()
    returns names and scopes only."""

    def __init__(self, path: str, master_key: str | None = None):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._key = _derive_key(master_key or resolve_master_key(
            str(self.path.parent / MASTER_KEYFILE_NAME), MASTER_KEY_ENV
        ))
        self._aead = AESGCM(self._key)
        self._records: dict[str, SecretRecord] = {}
        self._mtime_ns: int | None = None
        self._corrupt = False
        self._load()

    def exists_on_disk(self) -> bool:
        return self.path.is_file()

    def _stat_mtime_ns(self) -> int | None:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    @contextlib.contextmanager
    def _write_lock(self):
        """Cross-process write serialization: flock on a sibling .lock file so
        a `python -m ... vault` CLI write can't be clobbered by the daemon's
        cached-records persist (and vice versa). No fcntl → in-process lock
        only; reads deliberately stay lock-free since os.replace is atomic."""
        if fcntl is None:
            yield
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path.with_suffix(".lock"), "a+b") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def _load(self) -> None:
        """Rebuild _records from disk and swap atomically. Called under _lock
        on construction and by _maybe_reload when the file changed — e.g. a
        `python -m ... vault` CLI write while the daemon holds this vault.
        A deleted vault means "start fresh"; an unreadable existing file keeps
        prior state and marks the vault _corrupt so writes refuse to clobber
        data that may still be recoverable."""
        mtime = self._stat_mtime_ns()
        if mtime is None:
            self._records = {}
            self._mtime_ns = None
            self._corrupt = False
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            items = data["secrets"] if isinstance(data, dict) else None
            if not isinstance(items, list):
                raise ValueError("vault file: 'secrets' is not a list")
        except (OSError, ValueError):
            self._corrupt = True
            return
        fresh: dict[str, SecretRecord] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            scopes = item.get("scopes")
            fresh[name] = SecretRecord(
                name=name,
                scopes=[str(s) for s in scopes] if isinstance(scopes, list) else [],
                nonce_b64=str(item.get("nonce") or ""),
                ct_b64=str(item.get("ct") or ""),
            )
        self._records = fresh
        self._mtime_ns = mtime
        self._corrupt = False

    def _maybe_reload(self) -> None:
        """Caller must hold _lock. One stat per public op; reload only on change."""
        if self._stat_mtime_ns() != self._mtime_ns:
            self._load()

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "secrets": [
                {
                    "name": r.name,
                    "scopes": r.scopes,
                    "nonce": r.nonce_b64,
                    "ct": r.ct_b64,
                }
                for r in self._records.values()
            ],
        }
        # Per-process tmp name — a fixed sibling would be clobbered mid-write
        # when the daemon and the vault CLI persist concurrently.
        tmp = self.path.with_name(
            f"{self.path.name}.{os.getpid()}.{_secrets.token_hex(4)}.tmp"
        )
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        # Record OUR file's mtime before the rename (rename preserves it) —
        # statting self.path after replace could capture a foreign writer's.
        self._mtime_ns = tmp.stat().st_mtime_ns
        os.replace(tmp, self.path)

    def _encrypt(self, value: str) -> tuple[str, str]:
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ct).decode("ascii")

    def _decrypt(self, record: SecretRecord) -> str:
        nonce = base64.b64decode(record.nonce_b64)
        ct = base64.b64decode(record.ct_b64)
        return self._aead.decrypt(nonce, ct, None).decode("utf-8")

    def set(self, name: str, value: str, scopes: list[str] | None = None) -> None:
        name = name.strip()
        scopes = list(scopes or [])
        if not NAME_RE.match(name):
            raise ValueError(
                "invalid secret name — expected [A-Za-z0-9_.-/], 1-128 chars"
            )
        if not isinstance(value, str) or not value:
            raise ValueError("value required")
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            raise ValueError("value exceeds 64 KiB")
        if len(scopes) > 32 or any(
            not isinstance(s, str) or not SCOPE_RE.match(s) for s in scopes
        ):
            raise ValueError("invalid scopes")
        nonce_b64, ct_b64 = self._encrypt(value)
        with self._lock, self._write_lock():
            self._maybe_reload()
            if self._corrupt:
                raise ValueError(
                    "vault file unreadable — refusing to overwrite; "
                    "fix or remove it first"
                )
            self._records[name] = SecretRecord(
                name=name,
                scopes=scopes,
                nonce_b64=nonce_b64,
                ct_b64=ct_b64,
            )
            self._persist()

    def get(self, name: str, *, requester_scope: str | None = None) -> str | None:
        name = name.strip()
        with self._lock:
            self._maybe_reload()
            rec = self._records.get(name)
            if rec is None:
                return None
            if rec.scopes and requester_scope is not None:
                if requester_scope not in rec.scopes:
                    raise PermissionError(
                        f"secret '{name}' not in scope for '{requester_scope}'"
                    )
            return self._decrypt(rec)

    def list_meta(self) -> list[dict]:
        with self._lock:
            self._maybe_reload()
            return [
                {"name": r.name, "scopes": list(r.scopes)}
                for r in sorted(self._records.values(), key=lambda x: x.name)
            ]

    def delete(self, name: str) -> bool:
        name = name.strip()
        with self._lock, self._write_lock():
            self._maybe_reload()
            if self._corrupt or name not in self._records:
                return False
            del self._records[name]
            self._persist()
            return True

    def all_secret_values(self) -> list[str]:
        with self._lock:
            self._maybe_reload()
            vals: list[str] = []
            for name in list(self._records):
                try:
                    vals.append(self.get(name) or "")
                except Exception:
                    continue
            return [v for v in vals if v]


def redact_values(text: str, values: Iterable[str], min_length: int = 8) -> str:
    """Replace each known secret value in text with a mask token."""
    if not text:
        return text
    out = text
    for val in sorted(set(values), key=len, reverse=True):
        if not val or len(val) < min_length:
            continue
        out = out.replace(val, "***REDACTED***")
    return out


def mask_value(value: str) -> str:
    """Display form for a secret: bullets plus last four characters."""
    if not value:
        return ""
    tail = value[-4:] if len(value) >= 4 else ""
    return f"••••••••{tail}"


def mask_name_only(name: str, scopes: list[str] | None = None) -> str:
    """Display form for list/add output: name, bullets, and scopes only."""
    scope_s = ", ".join(scopes or []) or "—"
    return f"{name} •••••••• (scopes: {scope_s})"


def main(argv: list[str] | None = None) -> int:
    """`python -m usr.plugins.omaseal.helpers.vault add|list|delete` — the
    ops-shell write path for the plugin vault (parity with Khan's
    `python -m khan.secrets`). Runs standalone: point --vault-path at any
    vault file; the master key comes from --env-var, else the keyfile beside
    the vault unless --keyfile overrides it."""
    parser = argparse.ArgumentParser(
        prog="python -m usr.plugins.omaseal.helpers.vault"
    )
    parser.add_argument(
        "--vault-path", default="usr/secrets/omaseal/vault.enc",
        help="Vault file (default: %(default)s, relative to cwd)",
    )
    parser.add_argument(
        "--keyfile", default="",
        help=f"Master keyfile (default: {MASTER_KEYFILE_NAME} beside the vault file)",
    )
    parser.add_argument(
        "--env-var", default=MASTER_KEY_ENV,
        help="Env var read first for the master key (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Add or update a secret")
    p_add.add_argument("name")
    p_add.add_argument("--scope", default="", help="Comma-separated tool scopes")
    # no --value flag: secrets never travel in argv (ps / shell history).
    # piped stdin or a TTY prompt carries the value, like `omaseal set`.

    sub.add_parser("list", help="List secret names/scopes only")

    p_del = sub.add_parser("delete", help="Delete a secret by name")
    p_del.add_argument("name")

    args = parser.parse_args(argv)
    vpath = Path(args.vault_path)

    # list/delete on a missing vault must not create a keyfile — FileVault
    # construction resolves the master key, which writes one on first use.
    if args.cmd != "add" and not vpath.is_file():
        if args.cmd == "delete":
            print("not found")
            return 1
        return 0  # list on a missing vault: no output

    if args.cmd == "add":
        name = args.name.strip()
        if not NAME_RE.match(name):
            print(f"error: invalid secret name '{name}'", file=sys.stderr)
            return 2
        keyfile = Path(args.keyfile) if args.keyfile else (
            vpath.parent / MASTER_KEYFILE_NAME
        )
        # Refuse to mint a new key beside a populated vault — records under
        # the old key would become undecryptable.
        if (
            vpath.is_file() and vpath.stat().st_size > 0
            and not os.getenv(args.env_var, "").strip()
            and not keyfile.is_file()
        ):
            print(
                f"error: vault exists but no master key — set {args.env_var} "
                f"or restore {keyfile}",
                file=sys.stderr,
            )
            return 2
        try:
            if sys.stdin.isatty():
                value = getpass.getpass(f"Secret value for {name}: ")
            else:
                value = sys.stdin.read().rstrip("\n")
        except (EOFError, OSError):
            print(
                "error: no TTY — pipe the secret on stdin "
                "(e.g. `printf %s \"$KEY\" | … add NAME`)",
                file=sys.stderr,
            )
            return 2
        if not value:
            print("error: empty secret value", file=sys.stderr)
            return 2
        fv = FileVault(
            path=str(vpath),
            master_key=resolve_master_key(str(keyfile), args.env_var),
        )
        try:
            scopes = parse_scopes(args.scope)
            fv.set(name, value, scopes)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(mask_name_only(name, scopes))
        return 0

    fv = FileVault(
        path=str(vpath),
        master_key=resolve_master_key(
            args.keyfile or str(vpath.parent / MASTER_KEYFILE_NAME),
            args.env_var,
        ),
    )
    if args.cmd == "list":
        for meta in fv.list_meta():
            print(mask_name_only(meta["name"], meta["scopes"]))
        return 0
    ok = fv.delete(args.name)
    print("deleted" if ok else "not found")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
