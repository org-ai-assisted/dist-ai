#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Print the aggregate build-lane verdict for a commit's check-runs.
## Reads the GitHub `check-runs` JSON on stdin; env job_filter selects jobs.
## Emits one of: completed:<conclusion> / in_progress:None / (nothing).

import json, sys, os


def verdict():
    ## Contract: emit a verdict OR nothing. Any parse/shape error must yield NO
    ## verdict (the caller treats no output as "cannot read yet" and keeps
    ## waiting), never a stack-trace exit 1 -- the JSON here is a network payload
    ## whose shape is not guaranteed (an error body is a dict/list of the wrong
    ## shape; a truncated read is invalid JSON), so a missing key or a non-dict
    ## must not crash the watcher.
    flt = os.environ.get("job_filter", "uild")
    d = json.load(sys.stdin)
    all_runs = d.get("check_runs", []) if isinstance(d, dict) else []
    all_runs = [r for r in all_runs if isinstance(r, dict)]
    if not all_runs:
        return

    ## Decide over ALL build jobs, never last-one-wins. This lane has two
    ## (build (a) and build (b)); reporting the last one scanned would call the
    ## whole build a success while the other was still running.
    ##
    ## A commit can carry check-runs from MORE THAN ONE workflow run -- a rerun,
    ## or a fresh dispatch on the same head-sha. Each workflow run is exactly one
    ## check-suite, and suite ids grow with time, so a stale prior run's
    ## completed:failure must not outvote the current run still in progress. Pick
    ## the newest suite across EVERY check-run (NOT just the filtered ones): while
    ## the newest run is still in its build phase and has not created the filtered
    ## jobs yet (e.g. boot-test legs), the max over filtered jobs alone would fall
    ## back to a PRIOR run's suite and report that stale run's verdict.
    def suite_id(r):
        return (r.get("check_suite") or {}).get("id") or 0

    latest = max((suite_id(r) for r in all_runs), default=0)
    jobs = [r for r in all_runs
            if suite_id(r) == latest
            and flt in r.get("name", "") and "dry-run" not in r.get("name", "")]
    if not jobs:
        ## The newest suite has none of this job type yet -> nothing decided; keep
        ## waiting rather than reading a prior run's jobs on the same head-sha.
        return

    bad = [r for r in jobs
           if r.get("conclusion") not in (None, "success", "skipped")]
    if bad:
        return "completed:" + str(bad[0].get("conclusion"))
    if all(r.get("status") == "completed" for r in jobs):
        ## A SKIPPED job did not run, so it is not evidence of anything. Counting
        ## it as success reported "compare PASSED" for a compare that never
        ## executed because an upstream build had failed -- a job whose whole
        ## purpose is to produce a verdict, reported as having produced a good one.
        if any(r.get("conclusion") == "success" for r in jobs):
            return "completed:success"
        return "completed:skipped"
    return "in_progress:None"


try:
    result = verdict()
except Exception:
    sys.exit(0)
if result:
    print(result)
