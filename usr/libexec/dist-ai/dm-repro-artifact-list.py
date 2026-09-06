#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Read a GitHub run-artifacts API response on stdin and print one
## "id<TAB>name" line per unexpired artifact.

import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for item in payload.get("artifacts") or []:
    if item.get("expired"):
        continue
    print("%s\t%s" % (item["id"], item["name"]))
