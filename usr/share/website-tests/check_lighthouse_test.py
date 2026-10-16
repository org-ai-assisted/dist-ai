#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.lighthouse's browser-free engine: sample parse (incl. the
failed-audit marker + malformed rejection), best-of/worst-of reduction, baseline
parse/format roundtrip, the regression comparison (tolerance band inclusive, missing =
fail-closed), and the env tolerances. No browser. Run by the launcher or: ./check_lighthouse_test.py"""
import os
import sys


def _load():
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import lighthouse
    return lighthouse


lh = _load()


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write("check_lighthouse_test: %s %s\n" % (status, label))

    # parse_samples: a good line, the failed-audit marker, and hard-error on malformed.
    good = lh.parse_samples(["/ mobile 83 90 96"])
    ck(good == [(("/", "mobile"), {"perf": 83, "a11y": 90, "bp": 96})], "parses a score line")
    ck(lh.parse_samples(["/x desktop - - -"]) == [(("/x", "desktop"), None)],
       "failed-audit marker -> None (dropped by reducer)")
    for bad in ("/ mobile 83 90", "/ mobile 83 90 nine"):
        try:
            lh.parse_samples([bad])
            ck(False, "malformed line rejected: %r" % bad)
        except ValueError:
            ck(True, "malformed line rejected: %r" % bad)

    # reduce_samples: best-of (gate) keeps max, worst-of (seed) keeps min; an all-failed key is
    # surfaced as unmeasurable, never silently dropped.
    pairs = lh.parse_samples(["/ mobile 70 90 96", "/ mobile 80 88 96", "/x mobile - - -"])
    red_max, failed = lh.reduce_samples(pairs, how="max")
    ck(red_max[("/", "mobile")] == {"perf": 80, "a11y": 90, "bp": 96}, "max keeps per-cat best")
    ck(("/x", "mobile") in failed, "all-failed key surfaced as unmeasurable")
    red_min, _ = lh.reduce_samples(pairs, how="min")
    ck(red_min[("/", "mobile")] == {"perf": 70, "a11y": 88, "bp": 96}, "min keeps per-cat worst")

    # format_baseline / parse_baseline roundtrip (deterministic, reviewable).
    import tempfile
    from pathlib import Path
    sm = {("/", "mobile"): {"perf": 83, "a11y": 90, "bp": 96},
          ("/x", "desktop"): {"perf": 99, "a11y": 100, "bp": 100}}
    text = lh.format_baseline(sm, site="demo")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.txt"
        p.write_text(text, encoding="utf-8")
        ck(lh.parse_baseline(p) == sm, "format/parse baseline roundtrip")

    # compare: within tolerance passes (band inclusive); below floor fails; a key missing from
    # the baseline is a fail-closed MISSING regression.
    base = {("/", "mobile"): {"perf": 80, "a11y": 90, "bp": 96}}
    tol = {"perf": 8, "a11y": 2, "bp": 2}
    ck(lh.compare(base, {("/", "mobile"): {"perf": 72, "a11y": 88, "bp": 96}}, tol) == [],
       "fresh == baseline - tol PASSES (inclusive band)")
    regs = lh.compare(base, {("/", "mobile"): {"perf": 71, "a11y": 90, "bp": 96}}, tol)
    ck(len(regs) == 1 and regs[0].bad and regs[0].bad[0][0] == "perf",
       "perf below floor is a regression")
    missing = lh.compare(base, {("/new", "mobile"): {"perf": 99, "a11y": 99, "bp": 99}}, tol)
    ck(len(missing) == 1 and missing[0].missing, "a page missing from baseline fails closed")

    # tolerances default (perf wide, a11y/bp tight); env override honored.
    os.environ.pop("LH_TOL_PERF", None)
    ck(lh.tolerances_from_env() == {"perf": 8, "a11y": 2, "bp": 2}, "default tolerances")
    os.environ["LH_TOL_PERF"] = "15"
    try:
        ck(lh.tolerances_from_env()["perf"] == 15, "LH_TOL_PERF env override")
    finally:
        os.environ.pop("LH_TOL_PERF", None)

    # a failed/timed-out lighthouse audit must yield a dropped sample (None), never crash:
    # the handler must reference subprocess.TimeoutExpired, not the nonexistent
    # subprocess.TimeoutError (which would raise AttributeError when the except fires).
    import inspect
    src = inspect.getsource(lh._run_lighthouse)
    ck("subprocess.TimeoutExpired" in src and "subprocess.TimeoutError" not in src,
       "lighthouse failure handler uses TimeoutExpired (not the bogus TimeoutError)")

    sys.stdout.write("check_lighthouse_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
