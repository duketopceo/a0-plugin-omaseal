"""Path helpers for the omaseal plugin.

Resolves plugin-configured relative paths against the Agent Zero root. Uses
helpers.files.get_abs_path when the A0 framework is present; falls back to the
process working directory so the module stays testable standalone.
"""

from __future__ import annotations

import os
from pathlib import Path

try:  # A0 runtime
    from helpers.files import get_abs_path as _a0_abs_path
except Exception:  # standalone / tests
    _a0_abs_path = None


def abs_path(rel_or_abs: str) -> str:
    """Resolve a possibly-relative path against the A0 root."""
    if not rel_or_abs:
        return ""
    p = Path(rel_or_abs).expanduser()
    if p.is_absolute():
        return str(p)
    if _a0_abs_path is not None:
        try:
            return _a0_abs_path(str(p))
        except Exception:
            pass
    return str(Path.cwd() / p)


def plugin_root() -> Path:
    """Directory that contains this helpers/ package's parent (plugin root)."""
    return Path(__file__).resolve().parents[1]
