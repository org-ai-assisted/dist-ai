#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shell-invocation guard.
"exec" "bash" "-c" "printf '%s\n' '$0: ERROR: Do not execute this script with bash!' >&2; exit 1"

"""Unit + canary tests for the dm-test-result/v1 schema model.

Canaries (each fails on a schema that is NOT no-false-green):
  - an unknown/empty step status coerces to `unknown`, never to `passed` (a model
    that defaulted a missing status to passed would fail this);
  - `validate` refuses a summary that disagrees with steps[] (a model that trusted
    a hand-supplied count would fail this);
  - rc 2 maps to run INCONCLUSIVE and step `broken`, distinct from FAIL/`failed`;
  - serialization is deterministic and ASCII.

Exit: 0 all pass, 1 any fail.
"""

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dm_test_results import model  # noqa: E402

_failures = 0


def check(label, cond):
    global _failures
    if cond:
        print("ok: %s" % label)
    else:
        print("FAIL: %s" % label, file=sys.stderr)
        _failures += 1


def check_raises(label, func):
    try:
        func()
    except model.ModelError:
        print("ok: %s" % label)
        return
    print("FAIL: %s (no ModelError raised)" % label, file=sys.stderr)
    global _failures
    _failures += 1


def _passed_step(name="s1"):
    return model.make_step(name=name, status=model.STATUS_PASSED, exit_code=0)


## verdict + step-status rc mapping (single source shared with the bash console line).
check("rc 0 -> PASS", model.verdict_from_rc(0) == model.VERDICT_PASS)
check("rc 2 -> INCONCLUSIVE", model.verdict_from_rc(2) == model.VERDICT_INCONCLUSIVE)
check("rc 5 -> FAIL", model.verdict_from_rc(5) == model.VERDICT_FAIL)
check("step rc 0 -> passed", model.step_status_from_rc(0) == model.STATUS_PASSED)
check("step rc 2 -> broken", model.step_status_from_rc(2) == model.STATUS_BROKEN)
check("step rc 5 -> failed", model.step_status_from_rc(5) == model.STATUS_FAILED)

## No-false-green keystone: an unknown/empty status is coerced to the fail-closed
## `unknown` sentinel, NEVER to passed.
check(
    "unknown status coerces to unknown (not passed)",
    model.make_step(name="x", status="bogus", exit_code=0)["status"] == model.STATUS_UNKNOWN,
)
check(
    "empty status coerces to unknown (not passed)",
    model.make_step(name="x", status="", exit_code=0)["status"] == model.STATUS_UNKNOWN,
)
check("the only green status is passed", model.STATUS_GREEN == model.STATUS_PASSED)

## A text-only step has an empty attachments[]; a screenshot step has one.
check("text-only step has no attachments", _passed_step()["attachments"] == [])
shot_step = model.make_step(
    name="r4", status=model.STATUS_PASSED, exit_code=0,
    attachments=[model.make_attachment("screenshot", "image/png", "r4.png")],
)
check("screenshot step has one attachment", len(shot_step["attachments"]) == 1)

## summary is derived and must agree with steps[]; validate refuses a mismatch.
built = model.build_result(
    run_id="lane-1", lane="kicksecure-lxqt", version="18.2.3.5",
    builder="dm-release-test", mode="calamares-install", origin=model.ORIGIN_DOWNLOADED,
    rc=0, generated_unix=1700000000, stop_unix=1700000000,
    expect=["Kicksecure"], steps=[_passed_step()],
)
check("summary passed count", built["summary"]["passed"] == 1)
check("summary total count", built["summary"]["total"] == 1)
check("reproducibility reserved null", built["reproducibility"] is None)
check("provenance origin preserved", built["provenance"]["origin"] == model.ORIGIN_DOWNLOADED)


def _tampered_summary():
    bad = model.build_result(
        run_id="lane-2", lane="l", version="v", builder="b", mode="m",
        origin=model.ORIGIN_BUILT, rc=0, generated_unix=1, stop_unix=1,
        steps=[_passed_step()],
    )
    bad["summary"]["passed"] = 999
    model.validate(bad)


check_raises("validate refuses summary that disagrees with steps", _tampered_summary)


def _bad_status():
    bad = model.build_result(
        run_id="lane-3", lane="l", version="v", builder="b", mode="m",
        origin=model.ORIGIN_BUILT, rc=0, generated_unix=1, stop_unix=1,
        steps=[_passed_step()],
    )
    bad["steps"][0]["status"] = "nonsense"
    model.validate(bad)


check_raises("validate refuses an invalid step status", _bad_status)
check_raises(
    "build_result refuses a bad origin",
    lambda: model.build_result(
        run_id="r", lane="l", version="v", builder="b", mode="m",
        origin="smuggled", rc=0, generated_unix=1, stop_unix=1, steps=[_passed_step()],
    ),
)

## time_pair: None stays None (unmeasured, rendered honestly); an int yields both forms.
check("time_pair(None) is None", model.time_pair(None) is None)
tp = model.time_pair(1700000000)
check("time_pair carries unix", tp["unix"] == 1700000000)
check("time_pair carries utc Z", tp["utc"] == "2023-11-14T22:13:20Z")
## An out-of-range time is a ModelError, not a raw OverflowError traceback (so the
## emitter reports it cleanly instead of crashing, and the publish fails cleanly).
check_raises("time_pair rejects an out-of-range unix", lambda: model.time_pair(10 ** 30))

## An attachment path must be a safe basename: no '/' and not '..' (it is written
## and served as-is). Canary for the root-write / escape-the-run-dir class.
check_raises(
    "attachment path rejects a slash",
    lambda: model.make_attachment("screenshot", "image/png", "a/b.png"),
)
check_raises(
    "attachment path rejects ..",
    lambda: model.make_attachment("screenshot", "image/png", ".."),
)
check(
    "a plain basename attachment path is accepted",
    model.make_attachment("screenshot", "image/png", "r4-first-boot.png")["path"]
    == "r4-first-boot.png",
)

## Deterministic + ASCII serialization.
a = model.dumps(built)
b = model.dumps(built)
check("dumps is byte-identical over identical input", a == b)
check("dumps ends with newline", a.endswith("\n"))
try:
    a.encode("ascii")
    check("dumps is ASCII", True)
except UnicodeEncodeError:
    check("dumps is ASCII", False)

if _failures:
    print("\n%d model assertion(s) failed" % _failures, file=sys.stderr)
    sys.exit(1)
print("\nall model assertions passed")
