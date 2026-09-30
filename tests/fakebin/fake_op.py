#!/usr/bin/env python3
"""Fake `op` CLI for tests. FAKE_OP_STORE is a JSON file mapping full
op:// references to values.

  op read <ref>  -> prints raw secret, exit 1 if absent
"""

import json
import os
import sys


def main(argv):
    path = os.environ.get("FAKE_OP_STORE", "")
    store = {}
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
    if len(argv) >= 3 and argv[1] == "read":
        ref = argv[2]
        if ref in store:
            sys.stdout.write(store[ref])
            return 0
        print("error: item not found", file=sys.stderr)
        return 1
    print("error: usage", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
