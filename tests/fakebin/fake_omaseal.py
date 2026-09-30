#!/usr/bin/env python3
"""Fake `omaseal` CLI for tests. Reads its fixture path from
FAKE_OMASEAL_STORE (a JSON file mapping "service/account" -> value). Mimics:
  get <service> <account>   -> prints raw secret, exit 1 if absent
  resolve <service> <acct>  -> same as get
  list --json               -> prints [{service,account,label}]
Anything else -> exit 2. Never prints a value for a name it does not hold.
"""

import json
import os
import sys


def load():
    path = os.environ.get("FAKE_OMASEAL_STORE", "")
    if not path or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    store = load()
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd in ("get", "resolve") and len(argv) == 4:
        key = f"{argv[2]}/{argv[3]}"
        if key in store:
            sys.stdout.write(store[key])
            return 0
        print("error: not found", file=sys.stderr)
        return 1
    if cmd == "list" and "--json" in argv:
        items = [
            {"service": k.split("/", 1)[0], "account": k.split("/", 1)[1],
             "label": k}
            for k in sorted(store) if "/" in k
        ]
        print(json.dumps(items))
        return 0
    print("error: usage", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
