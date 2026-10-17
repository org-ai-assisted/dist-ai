#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.axe's pure (browser-free) engine: target normalization (incl.
the frame/shadow boundary shapes), violation -> (path, rule, target) key mapping, baseline
parse/format roundtrip, and the accept-baseline comparison -- a NEW violation fails, a baselined
one passes, a resolved one is reported, and a MISSING baseline fails CLOSED. Run by the
website-tests launcher (a required unit) or directly: ./check_axe_test.py"""
import inspect
import os
import sys
import tempfile
from pathlib import Path


def _load():
    # the axe gate lives in the importable core; import it (its real home). Prepend this tree's
    # dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import axe
    return axe


ax = _load()


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            "check_axe_test: %s %s\n" % (status, label))

    # normalize_target: a single-element list is the plain selector; a multi-entry list is a
    # frame/shadow boundary path joined with ' >> '; a nested list (shadow hop) joins with a
    # space; a bare string and an unexpected type degrade to str() rather than raise.
    ck(ax.normalize_target(["button.foo"]) == "button.foo", "normalize single selector")
    ck(ax.normalize_target(["#frame", "button"]) == "#frame >> button",
       "normalize frame boundary path")
    ck(ax.normalize_target([["#host", "button"]]) == "#host button",
       "normalize nested shadow-DOM selector")
    ck(ax.normalize_target("a.bare") == "a.bare", "normalize bare string")
    ck(ax.normalize_target(None) == "None", "normalize unexpected type -> str")

    # result_keys: one (path, rule, target) key PER NODE; two nodes of one rule are two keys; a
    # clean page yields none; a nodeless violation contributes nothing (no element to key).
    sample = [
        {"id": "color-contrast", "nodes": [{"target": ["h1.kicker"]},
                                           {"target": ["p.lead"]}]},
        {"id": "image-alt", "nodes": [{"target": ["img.logo"]}]},
    ]
    keys = ax.result_keys("/", sample)
    ck(set(keys) == {("/", "color-contrast", "h1.kicker"),
                     ("/", "color-contrast", "p.lead"),
                     ("/", "image-alt", "img.logo")} and len(keys) == 3,
       "result_keys one key per node across rules: %s" % keys)
    ck(ax.result_keys("/", []) == [], "result_keys clean page -> no keys")
    ck(ax.result_keys("/", None) == [], "result_keys None violations -> no keys")
    ck(ax.result_keys("/x", [{"id": "region", "nodes": []}]) == [],
       "result_keys nodeless violation -> no keys")

    # parse_baseline / format_baseline roundtrip (deterministic, reviewable); a target with
    # spaces survives (split on the first two tokens only); blank / '#' lines are ignored; a
    # path+rule with no target roundtrips to an empty target.
    sm = {("/", "color-contrast", "main > h1.title span"),
          ("/wiki/A", "image-alt", "img.logo"),
          ("/", "region", "")}
    text = ax.format_baseline(sm, site="demo")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.txt"
        p.write_text(text, encoding="utf-8")
        ck(ax.parse_baseline(p.read_text(encoding="utf-8")) == sm,
           "format/parse baseline roundtrip (spaced + empty target)")
    ck(ax.parse_baseline("# header\n\n/ image-alt img\n") == {("/", "image-alt", "img")},
       "parse_baseline skips blank/comment lines")
    for bad in ("justpath",):
        try:
            ax.parse_baseline(bad)
            ck(False, "malformed baseline line rejected: %r" % bad)
        except ValueError:
            ck(True, "malformed baseline line rejected: %r" % bad)

    # evaluate: the heart of the regression model.
    a = ("/", "color-contrast", "h1")
    b = ("/", "image-alt", "img.logo")
    # a NEW violation (fresh, not baselined) fails.
    rc, new, resolved = ax.evaluate(True, set(), {a})
    ck(rc == 1 and new == [a] and resolved == [], "a NEW violation fails the gate")
    # a BASELINED violation (in both) passes and is not reported new.
    rc, new, resolved = ax.evaluate(True, {a}, {a})
    ck(rc == 0 and new == [] and resolved == [], "a baselined violation passes (tolerated)")
    # a RESOLVED violation (baselined, no longer firing) passes and is reported, not required.
    rc, new, resolved = ax.evaluate(True, {a}, set())
    ck(rc == 0 and new == [] and resolved == [a], "a resolved violation is reported, not required")
    # mixed: one accepted, one new -> fail on the new one only.
    rc, new, resolved = ax.evaluate(True, {a}, {a, b})
    ck(rc == 1 and new == [b] and resolved == [], "mixed: only the NEW violation fails")
    # a MISSING baseline fails CLOSED -- even with a fresh set, and even when fresh is EMPTY (an
    # unseeded site cannot pass by being incidentally clean).
    rc, new, _ = ax.evaluate(False, set(), {a})
    ck(rc == 1 and new == [a], "missing baseline fails closed (with fresh violations)")
    rc, new, _ = ax.evaluate(False, set(), set())
    ck(rc == 1 and new == [], "missing baseline fails closed (even when fresh is empty)")

    # resolve_axe_source honors AXE_SOURCE when it points at a real file; otherwise falls through.
    with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as tmp:
        axe_js = tmp.name
    try:
        os.environ["AXE_SOURCE"] = axe_js
        ck(ax.resolve_axe_source() == axe_js, "resolve_axe_source honors AXE_SOURCE file")
        os.environ["AXE_SOURCE"] = axe_js + ".nonexistent"
        got = ax.resolve_axe_source()
        ck(got != axe_js + ".nonexistent", "resolve_axe_source ignores a nonexistent AXE_SOURCE")
    finally:
        os.environ.pop("AXE_SOURCE", None)
        os.unlink(axe_js)

    # the family entry + the browser core exist with the expected shape.
    ck(callable(getattr(ax, "check_roots", None)), "check_roots family entry present")
    ck(callable(getattr(ax, "write_roots", None)), "write_roots (seed) entry present")
    ck("baseline_dir" in inspect.signature(ax.check_roots).parameters,
       "check_roots takes baseline_dir")

    # a missing chromium ENGINE is an env-unmet SKIP(77), not a hard FAIL -- check() guards the
    # launch like the sibling lanes (canary on the guard source).
    _check_src = inspect.getsource(ax.check)
    ck("except Exception as exc" in _check_src and "chromium engine unavailable" in _check_src,
       "check() turns a missing chromium engine into a SKIP, not a FAIL")

    # _skip raises SystemExit(77) (the shared env-unmet contract).
    try:
        ax._skip("canary")
        ck(False, "_skip raises SystemExit(77)")
    except SystemExit as exc:
        ck(exc.code == 77, "_skip raises SystemExit(77)")

    sys.stdout.write(
        "check_axe_test: %d pass, %d fail, 0 skip\n" % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
