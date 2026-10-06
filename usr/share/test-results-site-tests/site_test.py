#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Unit + canary tests for the generation-time run-cell classifier (site.py).

The no-false-green keystone, asserted exhaustively: a run cell is green ONLY when
it is a finished, fresh, functional PASS with every screenshot an approved MATCH.
STALE, NEW, CHANGED, UNKNOWN(shot), INCONCLUSIVE, incomplete and no-data each
yield a non-green status -- and the age is always carried so an old pass reads old.

Exit: 0 all pass, 1 any fail.
"""

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dm_test_results import compare, model, site  # noqa: E402

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


NOW = 1_700_000_000
WINDOW = site.DEFAULT_STALE_SECONDS


def make_result(rc=0, stop_unix=NOW, stage=model.STAGE_FINISHED):
    step = model.make_step(name="r4", status=model.step_status_from_rc(rc), exit_code=rc)
    return model.build_result(
        run_id="kicksecure-lxqt-18-2-3-5-1",
        lane="kicksecure-lxqt", version="18.2.3.5", builder="dm-release-test",
        mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=rc, generated_unix=NOW, stop_unix=stop_unix, stage=stage,
        steps=[step],
    )


def status_of(result, shots, now=NOW, window=WINDOW):
    return site.run_cell_status(result, shots, now, window)[0]


## The ONE green path: finished, fresh, PASS, all shots MATCH.
st, age = site.run_cell_status(make_result(rc=0), [compare.BUCKET_MATCH], NOW, WINDOW)
check("finished fresh PASS + MATCH is green", st == site.STATUS_PASS and site.is_green(st))
check("green run still carries an age", age is not None)

## PASS with NO shots (text-only run) is green.
check("finished fresh PASS + no shots is green", status_of(make_result(0), []) == site.STATUS_PASS)

## Every non-green path (none is STATUS_PASS, so none is green).
check("FAIL is fail", status_of(make_result(5), []) == site.STATUS_FAIL)
check("INCONCLUSIVE is inconclusive", status_of(make_result(2), []) == site.STATUS_INCONCLUSIVE)
check("unfinished run is incomplete", status_of(make_result(0, stage=model.STAGE_RUNNING), []) == site.STATUS_INCOMPLETE)
check("no result is nodata", status_of(None, []) == site.STATUS_NODATA)
check("missing stop is nodata/incomplete (not green)", not site.is_green(status_of(None, [])))

## A PASS that is too old is STALE, never green -- an old pass reads old.
stale = make_result(0, stop_unix=NOW - WINDOW - 1)
st_stale, age_stale = site.run_cell_status(stale, [compare.BUCKET_MATCH], NOW, WINDOW)
check("stale PASS is stale (not green)", st_stale == site.STATUS_STALE and not site.is_green(st_stale))
check("stale age exceeds the window", age_stale > WINDOW)

## A future stop time (clock skew or tampering) must NOT read green: a negative age
## is never stale, so without the guard a future-dated PASS would stay green forever.
future = make_result(0, stop_unix=NOW + 10 ** 9)
st_future, age_future = site.run_cell_status(future, [compare.BUCKET_MATCH], NOW, WINDOW)
check("future-dated PASS is not green", not site.is_green(st_future))
check("future age is negative", age_future < 0)

## A functional PASS with an unapproved / changed / errored shot is held out of green.
check("PASS + NEW shot is new", status_of(make_result(0), [compare.BUCKET_NEW]) == site.STATUS_NEW)
check("PASS + CHANGED shot is changed", status_of(make_result(0), [compare.BUCKET_CHANGED]) == site.STATUS_CHANGED)
check("PASS + UNKNOWN shot is unknown", status_of(make_result(0), [compare.BUCKET_UNKNOWN]) == site.STATUS_UNKNOWN)

## None of the non-green statuses is green (exhaustive guard).
for st in (
    site.STATUS_FAIL, site.STATUS_INCONCLUSIVE, site.STATUS_INCOMPLETE, site.STATUS_NODATA,
    site.STATUS_STALE, site.STATUS_NEW, site.STATUS_CHANGED, site.STATUS_UNKNOWN,
):
    check("%s is not green" % st, not site.is_green(st))
check("only STATUS_PASS is green", site.STATUS_GREEN == site.STATUS_PASS)

## Functional failure outranks a shot-approval state (a FAIL with a NEW shot reads
## fail, not new) -- the salient caveat wins, both are non-green.
check("FAIL outranks NEW shot", status_of(make_result(5), [compare.BUCKET_NEW]) == site.STATUS_FAIL)

## run_key groups the matrix; needs_approval flags NEW/CHANGED.
key = site.run_key(make_result(0))
check("run_key is (lane, version, builder, origin)",
      key == ("kicksecure-lxqt", "18.2.3.5", "dm-release-test", model.ORIGIN_DOWNLOADED))
check("needs_approval true for NEW", site.needs_approval([compare.BUCKET_NEW]))
check("needs_approval true for CHANGED", site.needs_approval([compare.BUCKET_CHANGED]))
check("needs_approval false for MATCH only", not site.needs_approval([compare.BUCKET_MATCH]))

## css_class is stable.
check("css_class(pass) is st-pass", site.css_class(site.STATUS_PASS) == "st-pass")

if _failures:
    print("\n%d site assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall site assertions passed")
