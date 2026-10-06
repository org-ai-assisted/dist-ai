## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Single source of truth for the per-run result.json schema (dm-test-result/v1).

The shape follows the cross-ecosystem test-report convention (CTRF envelope:
schema tag + explicit per-status summary counts + a steps[] array; epoch-second
timestamps; {name, mediaType, path} attachments), tightened with the honest enum
of richer runners (Allure/GitLab keep `broken` distinct from `failed`, and carry
an explicit `unknown`), plus a `stage`/`stop` split so a crashed or truncated run
is STRUCTURALLY detectable rather than silently green.

No-false-green invariants this module enforces:
  - A step `status` is REQUIRED and defaults to `unknown`. `passed` is never the
    absent/implied state, so truncated or missing data reads `unknown`, not green.
  - `stage` (did it finish) is separate from the per-step pass/fail outcome. A run
    with stage != "finished" or no `stop` cannot be presented as a clean result.
  - `summary` counts are explicit and are ASSERTED against steps[]; a mismatch is
    itself a corruption signal the generator can refuse on.

This module is pure: it builds, validates, and deterministically serializes the
model. It performs no filesystem or image work.
"""

import datetime
import json

SCHEMA = "dm-test-result/v1"

## Per-step functional status. `unknown` is the fail-closed default/sentinel: any
## absent, unmappable, or corrupt status lands here, never on `passed`.
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_BROKEN = "broken"
STATUS_SKIPPED = "skipped"
STATUS_TIMEDOUT = "timedout"
STATUS_UNKNOWN = "unknown"
STATUS_DEFAULT = STATUS_UNKNOWN
VALID_STATUS = (
    STATUS_PASSED,
    STATUS_FAILED,
    STATUS_BROKEN,
    STATUS_SKIPPED,
    STATUS_TIMEDOUT,
    STATUS_UNKNOWN,
)
## The ONE green status. Everything else (incl. skipped/unknown) is not green.
STATUS_GREEN = STATUS_PASSED

## Run-level functional verdict (the lane's overall outcome).
VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"

## Run lifecycle stage, orthogonal to the pass/fail outcome.
STAGE_SCHEDULED = "scheduled"
STAGE_RUNNING = "running"
STAGE_FINISHED = "finished"
STAGE_INTERRUPTED = "interrupted"
VALID_STAGE = (STAGE_SCHEDULED, STAGE_RUNNING, STAGE_FINISHED, STAGE_INTERRUPTED)

## Image provenance. `built` = we built it; `downloaded` = an official published
## artifact we fetched + signature-verified (the dm-release-test lane).
ORIGIN_BUILT = "built"
ORIGIN_DOWNLOADED = "downloaded"
VALID_ORIGIN = (ORIGIN_BUILT, ORIGIN_DOWNLOADED)


class ModelError(Exception):
    """A schema violation: invalid input, or summary that disagrees with steps."""


def verdict_from_rc(rc):
    """Map a lane rc to the run verdict. Single source so the console summary and
    result.json never drift: 0 = PASS; the reserved SETUP/inconclusive code 2 =
    INCONCLUSIVE (a provisioning/infra gap or inconclusive probe -- NOT a product
    failure, so neither green nor a leak); any other non-zero = FAIL."""
    if rc == 0:
        return VERDICT_PASS
    if rc == 2:
        return VERDICT_INCONCLUSIVE
    return VERDICT_FAIL


def step_status_from_rc(rc):
    """Map a step's exit code to its functional status, consistent with
    verdict_from_rc: 0 -> passed; 2 (SETUP/inconclusive) -> broken (an infra/setup
    error, distinct from an assertion failure); any other non-zero -> failed."""
    if rc == 0:
        return STATUS_PASSED
    if rc == 2:
        return STATUS_BROKEN
    return STATUS_FAILED


def _require_token(name, value):
    """A token sink (identifier/short label) must be a non-empty ASCII string with
    no control chars. Fail closed on anything else -- these land in a public page."""
    if not isinstance(value, str) or value == "":
        raise ModelError("%s must be a non-empty string" % name)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise ModelError("%s must be ASCII: %r" % (name, value))
    if any(ord(ch) < 0x20 for ch in value):
        raise ModelError("%s must not contain control characters: %r" % (name, value))
    return value


def _require_safe_component(name, value):
    """A value used as a single path component (a filename relative to the run dir)
    must contain no slash and be neither '.' nor '..', so it can never escape the
    run dir. Fail closed: an attachment path is written + served as-is."""
    _require_token(name, value)
    if "/" in value or value in (".", ".."):
        raise ModelError("%s must be a safe filename (no '/' or '..'): %r" % (name, value))
    return value


def time_pair(unix):
    """A timestamp as both wall-clock UTC (human) and epoch seconds (machine),
    derived from one integer so the two can never disagree. None -> None (an
    unmeasured time is rendered honestly, never faked)."""
    if unix is None:
        return None
    if not isinstance(unix, int) or isinstance(unix, bool):
        raise ModelError("unix time must be an int: %r" % (unix,))
    try:
        utc = datetime.datetime.fromtimestamp(
            unix, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError) as exc:
        raise ModelError("unix time out of range: %r (%s)" % (unix, exc))
    return {"utc": utc, "unix": unix}


def make_attachment(name, media_type, path):
    """One artifact reference: {name, mediaType, path}. path is relative to the run
    dir. A screenshot is just an attachment with an image/* mediaType -- there is no
    separate screenshot field, so text-only and screenshot steps share one shape."""
    return {
        "name": _require_token("attachment name", name),
        "mediaType": _require_token("attachment mediaType", media_type),
        "path": _require_safe_component("attachment path", path),
    }


def make_step(
    name,
    status,
    exit_code,
    start_unix=None,
    stop_unix=None,
    stdout_tail="",
    stderr_tail="",
    attachments=None,
):
    """One ordered step. `status` is required and must be a known value; an unknown
    or empty status is coerced to the fail-closed `unknown` sentinel, never dropped
    or defaulted to passed. attachments is 0+ (text-only step -> [])."""
    _require_token("step name", name)
    if status not in VALID_STATUS:
        status = STATUS_UNKNOWN
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise ModelError("step exit must be an int: %r" % (exit_code,))
    if attachments is None:
        attachments = []
    return {
        "name": name,
        "status": status,
        "rawStatus": str(exit_code),
        "exit": exit_code,
        "start": time_pair(start_unix),
        "stop": time_pair(stop_unix),
        "stdout_tail": stdout_tail if isinstance(stdout_tail, str) else "",
        "stderr_tail": stderr_tail if isinstance(stderr_tail, str) else "",
        "attachments": list(attachments),
    }


def summarize(steps):
    """Explicit per-status counts over steps[] (CTRF/GitLab convention: counts live
    in the envelope, not derived-only, so a summary-vs-steps mismatch is detectable).
    Every status key is always present so a reader never has to distinguish "0" from
    "absent"."""
    counts = {key: 0 for key in VALID_STATUS}
    for step in steps:
        counts[step["status"]] += 1
    counts["total"] = len(steps)
    return counts


def build_result(
    *,
    run_id,
    lane,
    version,
    builder,
    mode,
    origin,
    rc,
    generated_unix,
    stop_unix,
    test_user="",
    start_unix=None,
    stage=STAGE_FINISHED,
    expect=None,
    steps=None,
    provenance=None,
):
    """Assemble a dm-test-result/v1 document. `reproducibility` is reserved null (a
    later phase fills {determinism, rebuild} sub-blocks without moving any existing
    field). The result is validated before return."""
    _require_token("run id", run_id)
    _require_token("lane", lane)
    _require_token("mode", mode)
    _require_token("builder", builder)
    if origin not in VALID_ORIGIN:
        raise ModelError("origin must be one of %r: %r" % (VALID_ORIGIN, origin))
    if stage not in VALID_STAGE:
        raise ModelError("stage must be one of %r: %r" % (VALID_STAGE, stage))
    if not isinstance(rc, int) or isinstance(rc, bool):
        raise ModelError("rc must be an int: %r" % (rc,))
    if steps is None:
        steps = []
    if expect is None:
        expect = []
    for token in expect:
        _require_token("expect token", token)

    if provenance is None:
        provenance = {}
    prov = {
        "origin": origin,
        "artifact": {"digest": {"sha256": provenance.get("artifact_sha256")}},
        "source": {
            "uri": provenance.get("source_uri"),
            "gitCommit": provenance.get("source_commit"),
        },
        "builder": {"id": builder},
        "built_utc": provenance.get("built_utc"),
    }

    result = {
        "schema": SCHEMA,
        "generated": time_pair(generated_unix),
        "run": {
            "id": run_id,
            "lane": lane,
            "version": version if isinstance(version, str) else "",
            "mode": mode,
            "test_user": test_user if isinstance(test_user, str) else "",
            "builder": builder,
            "stage": stage,
            "start": time_pair(start_unix),
            "stop": time_pair(stop_unix),
            "rc": rc,
            "verdict": verdict_from_rc(rc),
            "expect": list(expect),
        },
        "summary": summarize(steps),
        "steps": list(steps),
        "provenance": prov,
        "reproducibility": None,
    }
    validate(result)
    return result


def validate(result):
    """Re-derive the summary from steps and refuse any disagreement, plus the
    structural no-false-green invariants. Also the UNTRUSTED-INPUT guard: a
    consumer (the site generator) validates a result.json it did not write with
    this, so run id / lane / attachment paths that would escape an output or
    golden dir are rejected here -- a malformed or hand-edited result is dropped
    (NO-DATA), never read. Raises ModelError on any violation."""
    ## Type-defensive throughout: a consumer validates an untrusted result.json, so
    ## a non-dict at any level must raise ModelError (-> NO-DATA), never an
    ## AttributeError/TypeError that escapes the caller's ModelError catch.
    if not isinstance(result, dict) or result.get("schema") != SCHEMA:
        raise ModelError("schema must be %r" % (SCHEMA,))
    run = result.get("run")
    if not isinstance(run, dict):
        raise ModelError("run must be an object")
    if run.get("stage") not in VALID_STAGE:
        raise ModelError("run.stage invalid: %r" % (run.get("stage"),))
    ## id + lane become path components (output dir, golden path); a '/' or '..'
    ## would escape. Keep them safe components.
    _require_safe_component("run.id", run.get("id"))
    _require_safe_component("run.lane", run.get("lane"))
    ## stop/start are read as (run.get(key) or {}).get("unix") by the generator
    ## (freshness, pruning) OUTSIDE a try; a truthy non-dict would raise there. Each
    ## must be null or an object whose unix (when present) is an int.
    for key in ("start", "stop"):
        val = run.get(key)
        if val is None:
            continue
        if not isinstance(val, dict):
            raise ModelError("run.%s must be null or an object: %r" % (key, val))
        unix = val.get("unix")
        if unix is not None and (not isinstance(unix, int) or isinstance(unix, bool)):
            raise ModelError("run.%s.unix must be an int: %r" % (key, unix))
    steps = result.get("steps")
    if not isinstance(steps, list):
        raise ModelError("steps must be a list")
    for step in steps:
        if not isinstance(step, dict):
            raise ModelError("each step must be an object")
        if step.get("status") not in VALID_STATUS:
            raise ModelError("step status invalid: %r" % (step.get("status"),))
        _require_safe_component("step.name", step.get("name"))
        attachments = step.get("attachments")
        if not isinstance(attachments, list):
            raise ModelError("step.attachments must be a list")
        for att in attachments:
            if not isinstance(att, dict):
                raise ModelError("each attachment must be an object")
            ## name AND path both become path components (name feeds the screenshot
            ## id -> golden path when a step has >1 shot), so both must be safe.
            _require_safe_component("attachment name", att.get("name"))
            _require_safe_component("attachment path", att.get("path"))
    expected = summarize(steps)
    if result.get("summary") != expected:
        raise ModelError(
            "summary disagrees with steps: %r != %r" % (result.get("summary"), expected)
        )
    return True


def dumps(result):
    """Deterministic ASCII serialization with a trailing newline. Field order is the
    dict insertion order above (stable), so re-emitting identical input yields a
    byte-identical file."""
    return json.dumps(result, ensure_ascii=True, indent=2, separators=(",", ": ")) + "\n"
