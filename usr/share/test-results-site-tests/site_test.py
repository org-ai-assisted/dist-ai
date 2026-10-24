#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

## AI-Assisted

"""Unit + canary tests for the generation-time run-cell classifier (site.py).

The status is OBJECTIVE -- decided purely from result.json, never from a screenshot
or a human golden approval. A run cell is green ONLY when it is a finished, fresh,
functional PASS on the declared firmware lane. STALE, INCONCLUSIVE, incomplete,
no-data and a firmware mismatch each yield a non-green status -- and the age is
always carried so an old pass reads old.

Exit: 0 all pass, 1 any fail.
"""

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dm_test_results import model, site  # noqa: E402 -- site/site_classes are numpy-free

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


def make_result(rc=0, stop_unix=NOW, stage=model.STAGE_FINISHED, environment=None):
    step = model.make_step(name="r4", status=model.step_status_from_rc(rc), exit_code=rc)
    return model.build_result(
        run_id="kicksecure-lxqt-18-2-3-5-1",
        lane="kicksecure-lxqt", version="18.2.3.5", builder="dm-release-test",
        mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
        rc=rc, generated_unix=NOW, stop_unix=stop_unix, stage=stage,
        steps=[step], environment=environment,
    )


def _firmware_env(match):
    return {"firmware": {
        "declared": "efi-secureboot", "detected": "BIOS" if match is False else "UEFI+SecureBoot",
        "evidence": "probe output", "match": match,
    }}


def status_of(result, now=NOW, window=WINDOW):
    return site.run_cell_status(result, now, window)[0]


## The ONE green path: finished, fresh, functional PASS. Screenshots never gate.
st, age = site.run_cell_status(make_result(rc=0), NOW, WINDOW)
check("finished fresh PASS is green", st == site.STATUS_PASS and site.is_green(st))
check("green run still carries an age", age is not None)

## REGRESSION keystone: there is NO human golden-approval gate. A finished, fresh PASS is
## green on its own objective merits -- it does NOT need an approved golden and is never held
## in a "needs approval" limbo. (This is the exact case the old NEW/CHANGED gate blocked.)
check("finished fresh PASS needs no golden approval to be green",
      status_of(make_result(0)) == site.STATUS_PASS)

## Every non-green path (none is STATUS_PASS, so none is green).
check("FAIL is fail", status_of(make_result(5)) == site.STATUS_FAIL)
check("INCONCLUSIVE is inconclusive", status_of(make_result(2)) == site.STATUS_INCONCLUSIVE)
check("unfinished run is incomplete", status_of(make_result(0, stage=model.STAGE_RUNNING)) == site.STATUS_INCOMPLETE)
check("no result is nodata", status_of(None) == site.STATUS_NODATA)
check("missing result is not green", not site.is_green(status_of(None)))

## A PASS that is too old is STALE, never green -- an old pass reads old.
stale = make_result(0, stop_unix=NOW - WINDOW - 1)
st_stale, age_stale = site.run_cell_status(stale, NOW, WINDOW)
check("stale PASS is stale (not green)", st_stale == site.STATUS_STALE and not site.is_green(st_stale))
check("stale age exceeds the window", age_stale > WINDOW)

## A future stop time (clock skew or tampering) must NOT read green: a negative age
## is never stale, so without the guard a future-dated PASS would stay green forever.
future = make_result(0, stop_unix=NOW + 10 ** 9)
st_future, age_future = site.run_cell_status(future, NOW, WINDOW)
check("future-dated PASS is not green", not site.is_green(st_future))
check("future age is negative", age_future < 0)

## Firmware EVIDENCE overrides a clean verdict: a finished fresh PASS whose captured
## environment.firmware.match is False provably booted the WRONG lane and must NOT be green
## (fail) -- otherwise a wrong-firmware boot is a false green. match True / None / absent (old
## or uncaptured runs) must NOT be forced to fail.
fw_mismatch = make_result(rc=0, environment=_firmware_env(False))
check("PASS + firmware mismatch is fail (not green)",
      status_of(fw_mismatch) == site.STATUS_FAIL and not site.is_green(status_of(fw_mismatch)))
check("PASS + firmware match stays green",
      status_of(make_result(rc=0, environment=_firmware_env(True))) == site.STATUS_PASS)
check("PASS + firmware match None stays green (uncaptured)",
      status_of(make_result(rc=0, environment=_firmware_env(None))) == site.STATUS_PASS)
check("PASS + no environment stays green (old run)",
      status_of(make_result(rc=0, environment=None)) == site.STATUS_PASS)
## _firmware_mismatch is type-defensive: a non-dict environment/firmware is "no evidence".
check("firmware mismatch false for non-dict environment",
      not site._firmware_mismatch({"environment": "oops"}))
check("firmware mismatch false for non-dict firmware",
      not site._firmware_mismatch({"environment": {"firmware": "oops"}}))

## None of the non-green statuses is green (exhaustive guard over the whole vocabulary).
for st in (
    site.STATUS_FAIL, site.STATUS_INCONCLUSIVE, site.STATUS_INCOMPLETE, site.STATUS_NODATA,
    site.STATUS_STALE, site.STATUS_UNKNOWN,
):
    check("%s is not green" % st, not site.is_green(st))
check("only STATUS_PASS is green", site.STATUS_GREEN == site.STATUS_PASS)

## There is no NEW/CHANGED approval vocabulary any more (the human golden gate is gone).
check("no STATUS_NEW in site", not hasattr(site, "STATUS_NEW"))
check("no STATUS_CHANGED in site", not hasattr(site, "STATUS_CHANGED"))
check("no needs_approval in site", not hasattr(site, "needs_approval"))

## run_key groups the matrix.
key = site.run_key(make_result(0))
check("run_key is (lane, version, builder, origin)",
      key == ("kicksecure-lxqt", "18.2.3.5", "dm-release-test", model.ORIGIN_DOWNLOADED))

## css_class is stable.
check("css_class(pass) is st-pass", site.css_class(site.STATUS_PASS) == "st-pass")

if _failures:
    print("\n%d site assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall site assertions passed")
