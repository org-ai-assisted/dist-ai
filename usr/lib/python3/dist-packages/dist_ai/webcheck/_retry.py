## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared per-page audit retry for the browser-driven webcheck gates (axe, taptarget).

The deploy runs the two site lanes in PARALLEL, both driving chromium in the SINGLE sandbox qube, so
a page that audits fine in isolation can hit a TRANSIENT contention fault: a wall-clock WEDGE
(asyncio.TimeoutError -- the audit exceeding its budget under CPU contention) OR a non-timeout audit
ERROR (a dead-browser new_page, a navigation / evaluation exception). Both are NON-COMPLETIONS, not
results: a real violation needs a COMPLETED audit, so retrying a non-completion on a FRESH browser
only lets it COMPLETE (its violations are then reported) and can NEVER mask one -- a deterministic
error or violation recurs on EVERY attempt and is still caught. So BOTH fault kinds retry up to
`attempts` times, and the page fails only when EVERY attempt faults.

The per-page coroutine CREATES the page (so a wedged new_page is a bounded wedge and a dead-browser
new_page is a caught error, never an uncaught traceback that aborts the gate) and returns it STILL
OPEN; this helper times ONLY the audit and closes the page OUTSIDE the wall-clock budget, so a
completed audit (which returns BEFORE its close) is never discarded by a slow/failed teardown, and a
close can never convert an in-flight audit into a false wedge."""
import asyncio
from typing import Any, Awaitable, Callable, Optional, Tuple

# A non-completion fault: ("wedged", "") for a wall-clock timeout, ("audit error", "<detail>") for any
# other exception. The detail (the exception text, clipped) rides the DIAGNOSTIC log line only; the
# caller's recorded problem keeps the stable "<kind>: <path> [<vp>]" form that the baseline + deploy
# log parse, so the detail never perturbs it.
Fault = Tuple[str, str]


def _clip(detail: str) -> str:
    # One-line, bounded: an exception str can carry newlines or be huge; keep the log line legible.
    return detail.replace("\n", " ").replace("\r", " ")[:200]


async def _relaunch(p, browser) -> Optional[Any]:
    """Discard the (possibly stuck) browser best-effort and return a FRESH chromium, or None when it
    can no longer launch (the engine died MID-RUN). None tells the caller to record the remaining
    pages as problems and RETURN what it has collected (a hard FAIL) -- never a raised traceback that
    aborts every remaining page and docroot, and never a violation-masking SKIP."""
    if browser is not None:
        try:
            await asyncio.wait_for(browser.close(), timeout=5)
        except Exception:        # noqa: BLE001 -- a close that also errors/hangs changes nothing
            pass
    try:
        return await p.chromium.launch()
    except Exception:            # noqa: BLE001 -- engine gone mid-run
        return None


async def audit_with_retry(
        p, browser, open_and_audit: Callable[[Any], Awaitable[Tuple[Any, dict]]],
        hard_timeout: float, attempts: int, label: str,
) -> Tuple[Optional[dict], Optional[Any], Optional[Fault]]:
    """Run `open_and_audit(browser)` -> (page, result_dict) with the page STILL OPEN, under
    `hard_timeout`, retrying a wedge OR a transient audit error on a fresh browser up to `attempts`
    times. Returns `(result, browser, fault)`:
      * success               -> (result_dict, browser, None); the page is closed OUTSIDE the budget
                                 first, so the captured result is never lost to a slow/failed teardown.
      * every attempt faulted -> (None, browser_or_None, (kind, detail)); `browser` is None IFF the
                                 engine died mid-run (the caller then stops auditing but still records
                                 and returns what it has).
    `browser` in the return is ALWAYS the one to use for the next page (freshly relaunched after any
    fault). A RETRY diagnostic line is printed between attempts."""
    fault: Optional[Fault] = None
    for attempt in range(attempts):
        try:
            page, result = await asyncio.wait_for(open_and_audit(browser), timeout=hard_timeout)
        except asyncio.TimeoutError:
            fault = ("wedged", "")
        except Exception as exc:          # noqa: BLE001 -- any new_page / navigation / evaluation error
            fault = ("audit error", _clip(str(exc)))
        else:
            # Audit COMPLETED. Close this page OUTSIDE the budget (best-effort): the result is already
            # captured, so a slow/failed close cannot discard it.
            try:
                await asyncio.wait_for(page.close(), timeout=5)
            except Exception:        # noqa: BLE001 -- teardown only, nothing to recover
                pass
            return result, browser, None
        browser = await _relaunch(p, browser)
        if browser is None:
            return None, None, fault
        if attempt + 1 < attempts:
            print("RETRY     %s (%s; retrying on a fresh browser)" % (label, fault[0]), flush=True)
    return None, browser, fault
