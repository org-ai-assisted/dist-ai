## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Generation-time classification for the verification site: the run-cell status
and the no-false-green rule, kept here (pure, directly testable) rather than buried
in the HTML generator.

A run cell is GREEN only when every one of these holds:
  - a valid result.json was read (not NO-DATA),
  - the run finished (stage == finished),
  - the functional verdict is PASS,
  - the run is not stale (age <= stale window),
  - every screenshot is MATCH (an approved golden), and there is no UNKNOWN shot.
Anything else yields a non-green status. Status severity is ordered so the cell
shows the most serious caveat, but is_green is simply status == pass -- there is no
path on which stale / new / changed / no-data / inconclusive reads green.

Age is ALWAYS carried (age_seconds), so an old green reads as old even when its
functional verdict was PASS.
"""

from . import compare
from . import model

## Run-cell statuses. Only STATUS_PASS is green. CSS class = "st-<status>".
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_INCOMPLETE = "incomplete"
STATUS_NODATA = "nodata"
STATUS_STALE = "stale"
STATUS_UNKNOWN = "unknown"
STATUS_CHANGED = "changed"
STATUS_NEW = "new"

## The one green status.
STATUS_GREEN = STATUS_PASS

## Default staleness window: a run older than this is shown stale (never green),
## so an old result cannot masquerade as a current pass.
DEFAULT_STALE_SECONDS = 30 * 24 * 3600

## Screenshot buckets that hold a run out of green, most-serious first.
_SHOT_NONGREEN_ORDER = (
    (compare.BUCKET_UNKNOWN, STATUS_UNKNOWN),
    (compare.BUCKET_CHANGED, STATUS_CHANGED),
    (compare.BUCKET_NEW, STATUS_NEW),
)


def css_class(status):
    return "st-%s" % status


def is_green(status):
    return status == STATUS_GREEN


def run_age_seconds(result, now_unix):
    """Seconds since the run's stop time (its freshness anchor). None when there is
    no valid stop time -- which itself blocks green (handled by run_cell_status)."""
    if not isinstance(result, dict):
        return None
    run = result.get("run") or {}
    stop = run.get("stop") or {}
    stop_unix = stop.get("unix")
    if not isinstance(stop_unix, int) or isinstance(stop_unix, bool):
        return None
    return now_unix - stop_unix


def run_cell_status(result, shot_buckets, now_unix, stale_seconds=DEFAULT_STALE_SECONDS):
    """Return (status, age_seconds). status is one of the STATUS_* values; green iff
    status == STATUS_PASS. shot_buckets is the list of compare buckets for this run's
    screenshots (empty for a text-only run)."""
    ## NO-DATA: no parseable result at all.
    if not isinstance(result, dict):
        return STATUS_NODATA, None

    age = run_age_seconds(result, now_unix)
    run = result.get("run") or {}

    ## Did not finish -> cannot be a clean result, regardless of any verdict field.
    if run.get("stage") != model.STAGE_FINISHED or age is None:
        return STATUS_INCOMPLETE, age

    verdict = run.get("verdict")
    if verdict == model.VERDICT_FAIL:
        return STATUS_FAIL, age
    if verdict == model.VERDICT_INCONCLUSIVE:
        return STATUS_INCONCLUSIVE, age
    if verdict != model.VERDICT_PASS:
        ## An unknown/absent verdict is never green.
        return STATUS_INCOMPLETE, age

    ## Functional PASS. A shot compare error (UNKNOWN) is the next most serious.
    bucket_set = set(shot_buckets)
    if compare.BUCKET_UNKNOWN in bucket_set:
        return STATUS_UNKNOWN, age

    ## A PASS that is too old is shown stale, never green.
    if age > stale_seconds:
        return STATUS_STALE, age

    ## Unapproved visual change holds the run out of green.
    for bucket, status in _SHOT_NONGREEN_ORDER:
        if bucket in bucket_set:
            return status, age

    return STATUS_PASS, age


def run_key(result):
    """The matrix grouping key: (lane, version, builder, provenance-origin). The
    overview keeps the latest run per key; pruning keeps latest-per-key plus a
    bounded recent history."""
    run = result.get("run") or {}
    prov = result.get("provenance") or {}
    return (
        run.get("lane", ""),
        run.get("version", ""),
        run.get("builder", ""),
        prov.get("origin", ""),
    )


def needs_approval(shot_buckets):
    """True if any screenshot needs a human: NEW (first approval) or CHANGED
    (re-approval). UNKNOWN is an error, surfaced separately (not an approval task)."""
    return any(
        bucket in (compare.BUCKET_NEW, compare.BUCKET_CHANGED) for bucket in shot_buckets
    )
