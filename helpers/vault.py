"""Encrypted local vault for the omaseal plugin — ported from Khan's
helpers/khan_vault.py (AES-256-GCM file vault) into a standalone,
framework-independent module.

Differences from the original: no framework imports (paths are explicit or
resolved via helpers.paths), plugin-owned file locations, and the VaultBackend
protocol kept for symmetry with the external resolution chain.

Secrets never appear in list APIs; get() is in-process only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets as _secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

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


def resolve_master_key(keyfile: str, env_var: str) -> str:
    env = os.getenv(env_var)
    if env and env.strip():
        return env.strip()
    path = Path(keyfile)
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = _secrets.token_hex(32)
    path.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
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
            str(self.path.parent / ".master_key"), "OMASEAL_MASTER_KEY"
        ))
        self._records: dict[str, SecretRecord] = {}
        self._load()

    def exists_on_disk(self) -> bool:
        return self.path.is_file()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for item in data.get("secrets") or []:
            name = str(item.get("name") or "")
            if not name:
                continue
            self._records[name] = SecretRecord(
                name=name,
                scopes=list(item.get("scopes") or []),
                nonce_b64=str(item.get("nonce") or ""),
                ct_b64=str(item.get("ct") or ""),
            )

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
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _encrypt(self, value: str) -> tuple[str, str]:
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, value.encode("utf-8"), None)
        return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ct).decode("ascii")

    def _decrypt(self, record: SecretRecord) -> str:
        nonce = base64.b64decode(record.nonce_b64)
        ct = base64.b64decode(record.ct_b64)
        return AESGCM(self._key).decrypt(nonce, ct, None).decode("utf-8")

    def set(self, name: str, value: str, scopes: list[str] | None = None) -> None:
        name = name.strip()
        if not name or not value:
            raise ValueError("name and value required")
        nonce_b64, ct_b64 = self._encrypt(value)
        with self._lock:
            self._records[name] = SecretRecord(
                name=name,
                scopes=list(scopes or []),
                nonce_b64=nonce_b64,
                ct_b64=ct_b64,
            )
            self._persist()

    def get(self, name: str, *, requester_scope: str | None = None) -> str | None:
        with self._lock:
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
            return [
                {"name": r.name, "scopes": list(r.scopes)}
                for r in sorted(self._records.values(), key=lambda x: x.name)
            ]

    def delete(self, name: str) -> bool:
        with self._lock:
            if name not in self._records:
                return False
            del self._records[name]
            self._persist()
            return True

    def all_secret_values(self) -> list[str]:
        with self._lock:
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
