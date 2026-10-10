#!/usr/bin/env python3
"""Fake CLI that hangs forever — regression fixture for the _run
deadlock/negative-cache path. Spawns a pipe-holding child like the real
omaseal->pinentry chain did."""
import os
import subprocess
import sys
import time

if __name__ == "__main__":
    if os.environ.get("HANG_SPAWN_CHILD"):
        # hold our inherited stdout open past the parent's death, like
        # pinentry held omaseal's pipe past subprocess.run's kill
        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=sys.stdout, stderr=subprocess.DEVNULL,
        )
    time.sleep(60)
