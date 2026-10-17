## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Lighthouse REGRESSION gate: baseline store + comparison, plus the local-serve orchestration.

Generic webcheck lane, shared by the family Pages sites and the wiki stage sites. Scores do not
meet aspirational absolute floors (perf 90 / a11y 95 / bp 95) everywhere, so the gate is
REGRESSION-relative: a committed per-page, per-form-factor baseline of current scores, and a
fresh run FAILS only when a category drops meaningfully below its baseline (minus a per-category
tolerance). The engine below (parse/reduce/compare/format) is browser-free and unit-tested
(check_lighthouse_test.py); the orchestration serves each site checkout locally and runs the
`lighthouse` CLI against it (needs lighthouse + chromium -> the sandbox), both form factors.

Line format, shared by the committed baseline file AND the sample stream:

    <path> <form-factor> <perf> <a11y> <bp>

A sample whose audit FAILED is `<path> <ff> - - -` -- a placeholder the reducer drops (best-of),
so one flake does not poison a page whose other samples succeeded. A page whose samples ALL
failed is unmeasurable and fails CLOSED.

Per-category tolerance (perf is run-to-run noisy; a11y / best-practices are deterministic) via
LH_TOL_PERF / LH_TOL_A11Y / LH_TOL_BP. The gate keeps the per-category BEST (max) across samples;
the seeder keeps the per-category WORST (min) so the floor sits below normal variation.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Gated categories, in display order.
CATEGORIES: Tuple[str, ...] = ("perf", "a11y", "bp")
# Lighthouse's own category ids, in the same order.
_LH_CATEGORY_IDS: Tuple[str, ...] = ("performance", "accessibility", "best-practices")
FAIL_MARK = "-"

Key = Tuple[str, str]
Scores = Dict[str, int]
ScoreMap = Dict[Key, Scores]


def tolerances_from_env() -> Dict[str, int]:
    """Per-category regression tolerance (points) from the environment. perf wide (noisy),
    a11y / best-practices tight (deterministic). Comparison takes them as a param so tests
    stay env-independent."""
    return {
        "perf": int(os.environ.get("LH_TOL_PERF", "8")),
        "a11y": int(os.environ.get("LH_TOL_A11Y", "2")),
        "bp": int(os.environ.get("LH_TOL_BP", "2")),
    }


def parse_samples(lines) -> List[Tuple[Key, Optional[Scores]]]:
    """Parse `<path> <ff> <perf> <a11y> <bp>` lines into (key, scores) pairs in input order. A
    failed-audit sample (`- - -`) parses to (key, None). Blank / `#` lines are skipped. A line
    without exactly five fields, or a non-integer score, is a hard error (a malformed line must
    never read as 'no regression')."""
    out: List[Tuple[Key, Optional[Scores]]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 5:
            raise ValueError("expected '<path> <ff> <perf> <a11y> <bp>', got: %r" % line)
        path, ff, rest = parts[0], parts[1], parts[2:]
        if all(v == FAIL_MARK for v in rest):
            out.append(((path, ff), None))
            continue
        try:
            scores = {cat: int(v) for cat, v in zip(CATEGORIES, rest)}
        except ValueError as exc:
            raise ValueError("non-integer score in: %r" % line) from exc
        out.append(((path, ff), scores))
    return out


def reduce_samples(pairs: List[Tuple[Key, Optional[Scores]]],
                   how: str) -> Tuple[ScoreMap, Set[Key]]:
    """Collapse repeated samples of a key to one score set per category over the SUCCESSFUL
    samples. how='max' keeps the BEST (gate: absorb jitter + a single flake), how='min' the
    WORST (seed: floor below variation). Returns (reduced, failed) where `failed` is the keys
    whose every sample failed -- unmeasurable, surfaced as a fail-closed error."""
    if how not in ("max", "min"):
        raise ValueError("how must be 'max' or 'min', got %r" % how)
    pick = max if how == "max" else min
    reduced: ScoreMap = {}
    seen: Set[Key] = set()
    for key, scores in pairs:
        seen.add(key)
        if scores is None:
            continue
        if key not in reduced:
            reduced[key] = dict(scores)
        else:
            for cat in CATEGORIES:
                reduced[key][cat] = pick(reduced[key][cat], scores[cat])
    failed = {key for key in seen if key not in reduced}
    return reduced, failed


def parse_baseline(path: Path) -> ScoreMap:
    """Load a committed baseline file. A failure marker has no place in a committed baseline:
    treat it as a hard error rather than silently shrinking coverage."""
    out: ScoreMap = {}
    for key, scores in parse_samples(path.read_text(encoding="utf-8").splitlines()):
        if scores is None:
            raise ValueError(
                "failure marker ('- - -') in baseline for %s [%s] -- re-seed it"
                % (key[0], key[1]))
        out[key] = scores
    return out


def merge_baseline(existing: ScoreMap, fresh: ScoreMap) -> ScoreMap:
    """Union of existing + freshly-seeded keys, fresh winning. A partial re-seed updates only
    the pages it measured and leaves the rest intact."""
    return {**existing, **fresh}


def format_baseline(scores: ScoreMap, site: Optional[str] = None) -> str:
    """Render a baseline file: a header, then one sorted line per key. Deterministic sort so a
    re-seed diff is reviewable. parse_baseline(format_baseline(x)) == x."""
    who = (" for %s" % site) if site else ""
    header = [
        "# Lighthouse regression baseline%s. Fields: <path> <form-factor> <perf> <a11y> <bp>" % who,
        "# The gate FAILS when a fresh score drops below baseline minus the per-category",
        "# tolerance (LH_TOL_PERF/A11Y/BP). Seeded as the MIN over several live runs so normal",
        "# run-to-run variation stays above the floor. A re-seed is MERGED into this file.",
        "#   webcheck-lighthouse-sandbox --write-baseline <site-root>",
    ]
    body = [
        "%s %s " % (path, ff) + " ".join(str(scores[cat]) for cat in CATEGORIES)
        for (path, ff), scores in sorted(scores.items())
    ]
    return "\n".join(header + body) + "\n"


class Regression:
    """One page/form-factor that regressed or could not be measured."""

    def __init__(self, key: Key, scores: Optional[Scores],
                 bad: List[Tuple[str, int, int]], missing: bool = False,
                 unmeasurable: bool = False) -> None:
        self.key = key
        self.scores = scores
        self.bad = bad
        self.missing = missing
        self.unmeasurable = unmeasurable

    def line(self) -> str:
        path, ff = self.key
        tag = "%s [%s]" % (path, ff)
        if self.unmeasurable:
            return "FAIL    %-36s every sample failed to audit -- cannot measure it" % tag
        if self.missing:
            return ("MISSING %-36s no baseline entry -- re-seed with "
                    "'webcheck-lighthouse-sandbox --write-baseline'" % tag)
        assert self.scores is not None
        got = " ".join("%s=%d" % (cat, self.scores[cat]) for cat in CATEGORIES)
        why = " ".join("%s=%d<%d" % (cat, fresh, floor) for cat, fresh, floor in self.bad)
        return "FAIL    %-36s %s --%s" % (tag, got, (" " + why) if why else "")


def ok_line(key: Key, scores: Scores) -> str:
    path, ff = key
    tag = "%s [%s]" % (path, ff)
    got = " ".join("%s=%d" % (cat, scores[cat]) for cat in CATEGORIES)
    return "ok      %-36s %s" % (tag, got)


def compare(baseline: ScoreMap, fresh: ScoreMap,
            tolerances: Dict[str, int]) -> List[Regression]:
    """Regressions in `fresh` vs `baseline`. A category fails when fresh < baseline - tol (so
    fresh == baseline - tol PASSES). A key absent from the baseline is a fail-closed regression
    (a new page must be seeded). Baseline keys with no fresh score are ignored (stale baseline)."""
    out: List[Regression] = []
    for key in sorted(fresh):
        scores = fresh[key]
        if key not in baseline:
            out.append(Regression(key, scores, [], missing=True))
            continue
        base = baseline[key]
        bad: List[Tuple[str, int, int]] = []
        for cat in CATEGORIES:
            floor = base[cat] - tolerances[cat]
            if scores[cat] < floor:
                bad.append((cat, scores[cat], floor))
        if bad:
            out.append(Regression(key, scores, bad))
    return out


# ---- orchestration (browser; runs where lighthouse + chromium live: the sandbox) -------------

# The family Pages sites are small; the homepage is the high-value regression signal (the
# heaviest, most-componentised page). Audited on BOTH form factors. Override with explicit paths.
_DEFAULT_PATHS: Tuple[str, ...] = ("/",)
# label -> extra lighthouse flag.
_FORM_FACTORS: Tuple[Tuple[str, str], ...] = (("mobile", ""), ("desktop", "--preset=desktop"))


def _run_lighthouse(url: str, extra_flag: str) -> Optional[Scores]:
    """One lighthouse audit of `url` -> {cat: score 0-100}, or None on any failure (crash,
    missing/garbled JSON). Chrome runs headless/--no-sandbox (already inside the sandbox qube)."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    try:
        cmd = ["lighthouse", url, "--quiet",
               "--only-categories=performance,accessibility,best-practices",
               "--chrome-flags=--headless=new --no-sandbox --disable-gpu",
               "--output=json", "--output-path=" + out_path]
        if extra_flag:
            cmd.insert(2, extra_flag)
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            # A timeout (TimeoutExpired is the real attribute name), a non-zero exit, or a
            # missing binary all mean "this audit produced no JSON" -> a failed sample (None),
            # which the reducer drops (best-of); it must NOT crash the whole run.
            return None
        try:
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
            cats = data["categories"]
            return {cat: round(cats[lh_id]["score"] * 100)
                    for cat, lh_id in zip(CATEGORIES, _LH_CATEGORY_IDS)}
        except (OSError, ValueError, KeyError, TypeError):
            return None
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def audit_root(root: str, paths: Tuple[str, ...], want_desktop: bool,
               samples: int) -> List[str]:
    """Serve `root` on a localhost mount (reusing mobile.py's harness) and run lighthouse over
    each (path, form-factor) `samples` times. Returns the raw sample lines
    (`<path> <ff> <perf> <a11y> <bp>`; `- - -` for a failed audit)."""
    from dist_ai.webcheck.mobile import _MountHandler, _MountingTCPServer
    factors = _FORM_FACTORS if want_desktop else _FORM_FACTORS[:1]
    handler = functools.partial(_MountHandler, directory=root)
    httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
    httpd.mounts = {}
    port = httpd.server_address[1]
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    lines: List[str] = []
    try:
        for path in paths:
            url = "http://127.0.0.1:%d%s" % (port, path if path.startswith("/") else "/" + path)
            for label, flag in factors:
                for _ in range(max(1, samples)):
                    scores = _run_lighthouse(url, flag)
                    if scores is None:
                        lines.append("%s %s - - -" % (path, label))
                    else:
                        lines.append("%s %s %d %d %d"
                                     % (path, label, scores["perf"], scores["a11y"],
                                        scores["bp"]))
    finally:
        httpd.shutdown()
    return lines


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    """Per-site baseline file, keyed by the checkout's basename."""
    return baseline_dir / ("lighthouse-baseline-%s.txt" % os.path.basename(os.path.normpath(root)))


def check_roots(roots: List[str], baseline_dir: str,
                paths: Tuple[str, ...] = _DEFAULT_PATHS) -> int:
    """FAMILY/stage entry (run in the sandbox): audit each root vs its committed baseline.
    SKIPs(77) when lighthouse is absent. Missing baseline for a root -> fail-closed MISSING."""
    import shutil
    if shutil.which("lighthouse") is None:
        _skip_77("lighthouse not installed")
    want_desktop = os.environ.get("LH_DESKTOP", "1") != "0"
    samples = int(os.environ.get("LH_SAMPLES", "2"))
    tolerances = tolerances_from_env()
    overall = 0
    for root in roots:
        bpath = _baseline_path(Path(baseline_dir), root)
        if not bpath.is_file():
            print("lighthouse: FAIL -- no baseline %s; seed with --write-baseline" % bpath,
                  file=sys.stderr)
            overall = 1
            continue
        baseline = parse_baseline(bpath)
        fresh, failed = reduce_samples(
            parse_samples(audit_root(root, paths, want_desktop, samples)), how="max")
        regressions = compare(baseline, fresh, tolerances)
        regressions += [Regression(key, None, [], unmeasurable=True) for key in sorted(failed)]
        regressed = {r.key for r in regressions}
        for r in sorted(regressions, key=lambda r: r.key):
            print("%s: %s" % (os.path.basename(root), r.line()))
        for key in sorted(fresh):
            if key not in regressed:
                print("%s: %s" % (os.path.basename(root), ok_line(key, fresh[key])))
        if regressions:
            overall = 1
    return overall


def write_roots(roots: List[str], baseline_dir: str,
                paths: Tuple[str, ...] = _DEFAULT_PATHS) -> int:
    """Seed/merge a per-site baseline from the MIN over LH_SEED_SAMPLES runs."""
    import shutil
    if shutil.which("lighthouse") is None:
        _skip_77("lighthouse not installed")
    want_desktop = os.environ.get("LH_DESKTOP", "1") != "0"
    seed_samples = int(os.environ.get("LH_SEED_SAMPLES", "5"))
    for root in roots:
        floor, failed = reduce_samples(
            parse_samples(audit_root(root, paths, want_desktop, seed_samples)), how="min")
        if failed or not floor:
            print("lighthouse: refusing to seed %s -- unmeasurable/empty" % root, file=sys.stderr)
            return 2
        bpath = _baseline_path(Path(baseline_dir), root)
        # A re-seed OVERWRITES, so a corrupt/failure-marked existing baseline must not abort it;
        # and the baseline dir may not exist yet (unlike the gate path, which reads it).
        try:
            existing = parse_baseline(bpath) if bpath.is_file() else {}
        except ValueError:
            existing = {}
        merged = merge_baseline(existing, floor)
        bpath.parent.mkdir(parents=True, exist_ok=True)
        bpath.write_text(format_baseline(merged, site=os.path.basename(os.path.normpath(root))),
                         encoding="utf-8")
        print("wrote %d baseline(s) -> %s" % (len(merged), bpath), file=sys.stderr)
    return 0


def _skip_77(msg: str) -> None:
    print("lighthouse: SKIP (%s)" % msg, file=sys.stderr)
    raise SystemExit(77)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Lighthouse regression gate (local-serve).")
    ap.add_argument("--baseline-dir", required=True,
                    help="dir holding lighthouse-baseline-<site>.txt")
    ap.add_argument("--write-baseline", action="store_true",
                    help="seed/merge the baseline (MIN over LH_SEED_SAMPLES runs) instead of gating")
    ap.add_argument("roots", nargs="+", help="site checkout root(s) with index.html")
    args = ap.parse_args(argv)
    from dist_ai.webcheck import cli
    # A named root that does not resolve FAILS loud (not a silent drop / skip). The _skip_77
    # above is for a genuinely-absent lighthouse BINARY (an optional environment tool), a
    # different thing from a mistyped root -- which is an operator error, so a failure.
    roots = cli.require_existing_dirs(args.roots, "lighthouse")
    if args.write_baseline:
        return write_roots(roots, args.baseline_dir)
    return check_roots(roots, args.baseline_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
