#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Read a GitHub git-ref API response on stdin and print the object SHA it
## names, or nothing when the body carries none (e.g. a "Not Found").

import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
obj = payload.get("object") if isinstance(payload, dict) else None
if isinstance(obj, dict) and obj.get("sha"):
    print(obj["sha"])
