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
all_runs = d.get("check_runs", [])
if not all_runs:
    sys.exit(0)
## A commit can carry check-runs from MORE THAN ONE workflow run -- a rerun, or a
## fresh dispatch on the same head-sha. Each workflow run is exactly one
## check-suite, and suite ids grow with time, so a stale prior run's
## completed:failure must not outvote the current run still in progress. Pick the
## newest suite across EVERY check-run (NOT just the filtered ones): while the
## newest run is still in its build phase and has not created the filtered jobs
## yet (e.g. boot-test legs), the max over filtered jobs alone would fall back to
## a PRIOR run's suite and report that stale run's verdict.
def _suite_id(r):
    return (r.get("check_suite") or {}).get("id") or 0
_latest = max((_suite_id(r) for r in all_runs), default=0)
jobs = [r for r in all_runs
        if _suite_id(r) == _latest
        and flt in r["name"] and "dry-run" not in r["name"]]
if not jobs:
    ## The newest suite has none of this job type yet -> nothing decided; keep
    ## waiting rather than reading a prior run's jobs on the same head-sha.
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
