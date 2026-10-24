## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Run-cell status for the verification site: objective, decided purely from
result.json, kept here (pure, directly testable) rather than buried in the HTML
generator.

A run cell is GREEN only when every one of these holds:
  - a valid result.json was read (not NO-DATA),
  - the run finished (stage == finished) with a trustworthy (non-future) stop time,
  - the functional verdict is PASS,
  - the firmware-lane evidence does not prove a wrong-lane boot, and
  - the run is not stale (age <= stale window).

Screenshots do NOT gate status: a blank/degenerate must-render frame is caught at
RUN time (image-blank-check, per-milestone, source-encoded in dm-calamares-install)
and fails the run there, so a PASS verdict already means every gated shot rendered.
There is no human golden-approval step -- shots are always published for inspection,
and correctness is objective. Age is ALWAYS carried (age_seconds), so an old green
reads as old even when its functional verdict was PASS.
"""

from . import model
## Re-export the status + css_class half of the pure-data contract from the numpy-free leaf
## module, so the required website-tests unit and the deploy-time contract check can import the
## manifest without pulling the image stack. Callers keep using site.STATUS_*, site.STATUS_GREEN,
## site.css_class unchanged.
from .site_classes import (
    STATUS_FAIL,
    STATUS_GREEN,
    STATUS_INCOMPLETE,
    STATUS_INCONCLUSIVE,
    STATUS_NODATA,
    STATUS_PASS,
    STATUS_STALE,
    STATUS_UNKNOWN,
    css_class,
)

## Public API (css_class is used only via site.css_class by the generator + site_test, an
## intentional re-export rather than a dead import).
__all__ = [
    'STATUS_PASS', 'STATUS_FAIL', 'STATUS_INCONCLUSIVE', 'STATUS_INCOMPLETE',
    'STATUS_NODATA', 'STATUS_STALE', 'STATUS_UNKNOWN',
    'STATUS_GREEN', 'css_class',
    'DEFAULT_STALE_SECONDS', 'CLOCK_SKEW_GRACE_SECONDS',
    'is_green', 'run_age_seconds', 'run_cell_status', 'run_key',
]

## Default staleness window: a run older than this is shown stale (never green),
## so an old result cannot masquerade as a current pass.
DEFAULT_STALE_SECONDS = 30 * 24 * 3600

## Tolerate minor builder-vs-publisher clock skew: a stop time a little ahead of
## the generator clock is fine, but one clearly in the future (tampered or badly
## skewed) is treated as incomplete so it can never read green via a negative age.
CLOCK_SKEW_GRACE_SECONDS = 300


def is_green(status):
    return status == STATUS_GREEN


def _firmware_mismatch(result):
    """True only when firmware EVIDENCE was captured and proves a wrong-lane boot:
    environment.firmware.match is exactly False. validate() now guarantees match is a bool or
    null, so the False singleton is the reliable signal (a non-bool like the string "false" is
    rejected at validation -> NO-DATA, never a silent green). Absent / None / uncaptured match
    does NOT block (old runs stay unaffected). Type-defensive: a non-dict environment or
    firmware is simply "no mismatch evidence", never a crash."""
    if not isinstance(result, dict):
        return False
    env = result.get("environment")
    if not isinstance(env, dict):
        return False
    firmware = env.get("firmware")
    if not isinstance(firmware, dict):
        return False
    return firmware.get("match") is False


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


def run_cell_status(result, now_unix, stale_seconds=DEFAULT_STALE_SECONDS):
    """Return (status, age_seconds). status is one of the STATUS_* values; green iff
    status == STATUS_PASS. Decided purely from result.json -- screenshots do not gate."""
    ## NO-DATA: no parseable result at all.
    if not isinstance(result, dict):
        return STATUS_NODATA, None

    age = run_age_seconds(result, now_unix)
    run = result.get("run") or {}

    ## Did not finish, no stop time, or a stop time in the FUTURE (clock skew or a
    ## tampered timestamp) -> cannot be trusted as a clean result. A negative age is
    ## never stale, so without this guard a future-dated PASS would read green
    ## forever; treat it as incomplete instead.
    if run.get("stage") != model.STAGE_FINISHED or age is None or age < -CLOCK_SKEW_GRACE_SECONDS:
        return STATUS_INCOMPLETE, age

    verdict = run.get("verdict")
    if verdict == model.VERDICT_FAIL:
        return STATUS_FAIL, age
    if verdict == model.VERDICT_INCONCLUSIVE:
        return STATUS_INCONCLUSIVE, age
    if verdict != model.VERDICT_PASS:
        ## An unknown/absent verdict is never green.
        return STATUS_INCOMPLETE, age

    ## Functional PASS. Firmware EVIDENCE overrides the verdict: if the guest provably
    ## booted a lane other than the one declared (environment.firmware.match is False), the
    ## run tested the wrong firmware and is never green, regardless of verdict.
    if _firmware_mismatch(result):
        return STATUS_FAIL, age

    ## A PASS that is too old is shown stale, never green.
    if age > stale_seconds:
        return STATUS_STALE, age

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
