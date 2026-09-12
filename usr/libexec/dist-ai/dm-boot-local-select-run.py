#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the id of the newest successful Build/Boot Test workflow run.
## Reads the GitHub `actions/runs` JSON on stdin; prints one run id (or nothing).

import json
import sys

## The stdin body is a network payload whose shape is not guaranteed: a GitHub
## error object ({"message": ...}), a bare list/null an intercepting proxy or an
## error page can produce, or a truncated read. Any of these must yield no id
## and exit 0 -- the caller (dm-boot-local) reads an empty result as "no run
## found" and prints its own diagnostic. A stack-trace crash would instead abort
## the whole tool under the caller's errexit.
try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
if not isinstance(payload, dict):
    raise SystemExit(0)
for run in payload.get("workflow_runs") or []:
    if not isinstance(run, dict):
        continue
    if run.get("name") in ("Boot Test", "Build") and run.get("conclusion") == "success":
        run_id = run.get("id")
        if run_id is not None:
            print(run_id)
            break
