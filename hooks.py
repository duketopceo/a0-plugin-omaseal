"""Lifecycle hooks for the omaseal plugin.

Runs inside the A0 framework runtime. install() probes for the omaseal and
op CLIs and records what it found so tools can report clear backend status
instead of opaque subprocess failures. Never raises — a host without either
binary simply leaves those legs of the resolution chain offline.
"""

from __future__ import annotations

import json

from usr.plugins.omaseal.helpers import resolve as R
from usr.plugins.omaseal.helpers.paths import plugin_root

_PROBE_FILE = ".omaseal-probe.json"


def _write_probe() -> dict:
    status = R.backend_status()
    try:
        (plugin_root() / _PROBE_FILE).write_text(
            json.dumps({"backends": status}, indent=2) + "\n", encoding="utf-8"
        )
    except OSError:
        pass
    return status


def install():
    _write_probe()


def pre_update():
    # No plugin-owned processes or vendored binaries.
    pass


def uninstall():
    # Intentionally leaves the plugin vault (usr/secrets/omaseal/) in place —
    # deleting stored secrets on uninstall would be data loss. Documented in
    # README; remove that directory manually to fully purge.
    pass
