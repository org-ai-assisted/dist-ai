#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the aggregate build-lane verdict for a commit's check-runs.
## Reads the GitHub `check-runs` JSON on stdin; env job_filter selects jobs.
## Emits one of: completed:<conclusion> / in_progress:None / (nothing).

import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
## Decide over ALL build jobs, never last-one-wins. This lane has two
## (build (a) and build (b)); reporting the last one scanned would call the
## whole build a success while the other was still running.
import os
flt = os.environ.get("job_filter", "uild")
jobs = [r for r in d.get("check_runs", [])
        if flt in r["name"] and "dry-run" not in r["name"]]
if not jobs:
    sys.exit(0)
bad = [r for r in jobs
       if r["conclusion"] not in (None, "success", "skipped")]
if bad:
    print("completed:" + str(bad[0]["conclusion"]))
elif all(r["status"] == "completed" for r in jobs):
    ## A SKIPPED job did not run, so it is not evidence of anything. Counting it
    ## as success reported "compare PASSED" for a compare that never executed
    ## because an upstream build had failed -- a job whose whole purpose is to
    ## produce a verdict, reported as having produced a good one.
    if any(r["conclusion"] == "success" for r in jobs):
        print("completed:success")
    else:
        print("completed:skipped")
else:
    print("in_progress:None")
