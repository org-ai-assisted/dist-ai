#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Read a GitHub workflow-runs API response on stdin and print the id of the
## first (most recent) run, or nothing when the body lists none.

import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
runs = payload.get("workflow_runs") or []
if runs:
    print(runs[0]["id"])
