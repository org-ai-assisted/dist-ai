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
from typing import Any, Awaitable, Callable, Optional


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

    # _load_paths_file: the curated-sample path list (one root-relative path per line, blank/#
    # skipped) that restricts a huge tree (the ~9000-page wikis) to a representative subset.
    with tempfile.TemporaryDirectory() as _td:
        pf = Path(_td) / "paths.txt"
        pf.write_text("# curated\n\n/\n/wiki/ISO\n  /wiki/Donors  \n", encoding="utf-8")
        ck(ax._load_paths_file(str(pf)) == ["/", "/wiki/ISO", "/wiki/Donors"],
           "_load_paths_file strips blank/# + whitespace, preserves order")

    # _restrict_baseline: a curated CHECK compares only the audited paths' keys (an unvisited
    # baseline entry must NOT read as 'resolved').
    bl = {("/", "image-alt", "img"), ("/wiki/ISO", "color-contrast", "a"), ("/wiki/Other", "x", "y")}
    ck(ax._restrict_baseline(bl, None) == bl, "_restrict_baseline None -> whole baseline")
    ck(ax._restrict_baseline(bl, ["/", "/wiki/ISO"])
       == {("/", "image-alt", "img"), ("/wiki/ISO", "color-contrast", "a")},
       "_restrict_baseline keeps only audited paths' keys")

    # _merge_seed: a curated SEED keeps unvisited pages' accepted entries, replaces only audited.
    existing = {("/", "old", "a"), ("/wiki/Other", "keep", "b")}
    fresh = {("/", "new", "c")}
    ck(ax._merge_seed(existing, fresh, None) == fresh, "_merge_seed None -> replace whole set")
    ck(ax._merge_seed(existing, fresh, ["/"]) == {("/", "new", "c"), ("/wiki/Other", "keep", "b")},
       "_merge_seed restricted keeps unvisited, replaces audited paths")

    # An empty --paths-file is REJECTED (never silently falls back to a full-tree audit).
    with tempfile.TemporaryDirectory() as _td2:
        empty = Path(_td2) / "empty.txt"
        empty.write_text("# only a comment\n\n", encoding="utf-8")
        ck(ax.main(["--baseline-dir", _td2, "--paths-file", str(empty), _td2]) == 2,
           "main rejects an empty --paths-file (rc=2, no full-tree fallback)")
        # The callable entry points also reject an empty restriction (vacuous-audit guard),
        # before any chromium launch.
        ck(ax.check_roots([_td2], _td2, restrict=[]) == 2,
           "check_roots rejects an empty restriction (rc=2)")
        ck(ax.write_roots([_td2], _td2, restrict=[]) == 2,
           "write_roots rejects an empty restriction (rc=2)")

    # Canonical page identity: curated (extensionless), full (.html from _page_urls), and committed
    # .html baselines collapse to ONE key form, so a full-seeded baseline checked curated reports
    # no false NEW (CodeRabbit #766 Major).
    ck(ax._canon_path("/wiki/ISO.html") == "/wiki/ISO", "canon strips a trailing .html")
    ck(ax._canon_path("/wiki/ISO") == "/wiki/ISO", "canon leaves an extensionless path")
    ck(ax._canon_path("/wiki/ISO") == ax._canon_path("/wiki/ISO.html"),
       "canon collapses the two spellings of one page")
    ck(ax._canon_path("/index.html") == "/", "canon root index.html -> / (leading slash kept)")
    ck(ax._canon_path("/wiki/Dev/index.html") == "/wiki/Dev/", "canon subdir index -> /dir/")
    ck(ax._canon_path("/") == "/", "canon / stays /")
    ck(ax._canon_path(ax._canon_path("/wiki/ISO.html")) == ax._canon_path("/wiki/ISO.html"),
       "canon is idempotent")
    # A baseline seeded FULL (.html key) checked CURATED (extensionless) reports 0 new: both
    # parse_baseline and result_keys canonicalize, and the restrict filter canonicalizes too.
    base_full = ax.parse_baseline("/wiki/ISO.html color-contrast h1\n")
    fresh_curated = set(ax.result_keys(
        "/wiki/ISO", [{"id": "color-contrast", "nodes": [{"target": ["h1"]}]}]))
    rc_m, new_m, _res = ax.evaluate(
        True, ax._restrict_baseline(base_full, ["/wiki/ISO"]), fresh_curated)
    ck(rc_m == 0 and new_m == [],
       "full-seeded .html baseline checked curated extensionless -> 0 new (%s)" % (new_m,))
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

    # check() must SURFACE a launch failure to the caller (raise _EngineUnavailable), never decide
    # SKIP itself -- only the caller knows whether anything has been audited yet.
    _check_src = inspect.getsource(ax.check)
    ck("except Exception as exc" in _check_src and "_EngineUnavailable" in _check_src,
       "check() raises _EngineUnavailable on a launch failure (caller decides SKIP vs FAIL)")

    # chromium-launch failure semantics: an env-unmet SKIP(77) is honest ONLY when nothing has been
    # audited yet. A launch failure AFTER an earlier docroot ran is a mid-run fault -> hard
    # overall=1, never a silent SKIP (the masked-failure the local-first lanes close). Drive
    # check_roots with _serve_and_audit stubbed (no browser); seed a fake playwright so the
    # import guard passes on a host without the engine.
    import types as _types
    sys.modules.setdefault("playwright", _types.ModuleType("playwright"))
    sys.modules.setdefault("playwright.async_api", _types.ModuleType("playwright.async_api"))
    _orig_sna = ax._serve_and_audit

    def _raise_engine(*_a, **_k):
        raise ax._EngineUnavailable("simulated launch failure")

    with tempfile.TemporaryDirectory() as _bdir, \
            tempfile.TemporaryDirectory() as _r1, \
            tempfile.TemporaryDirectory() as _r2, \
            tempfile.NamedTemporaryFile(suffix=".js", delete=False) as _axe:
        _axe_js = _axe.name
        os.environ["AXE_SOURCE"] = _axe_js
        try:
            # present (empty) baseline for the first root so its clean audit passes (rc=0), isolating
            # the mid-run engine failure as the ONLY thing that can set overall=1 in case (B).
            Path(_bdir, "axe-baseline-%s.txt" % os.path.basename(_r1)).write_text(
                "", encoding="utf-8")

            # (A) engine down from the start -> nothing audited -> SKIP(77).
            ax._serve_and_audit = _raise_engine
            try:
                ax.check_roots([_r1], _bdir)
                ck(False, "engine down from the start -> SKIP(77)")
            except SystemExit as exc:
                ck(exc.code == 77, "engine down from the start -> SKIP(77), not a FAIL")

            # (B) first docroot audits clean, the SECOND fails to launch -> hard overall=1, no SKIP.
            _calls = {"n": 0}

            def _sna_second_fails(*_a, **_k):
                _calls["n"] += 1
                if _calls["n"] == 1:
                    return (set(), [])          # first docroot: clean audit
                raise ax._EngineUnavailable("simulated mid-run launch failure")

            ax._serve_and_audit = _sna_second_fails
            _rc = ax.check_roots([_r1, _r2], _bdir)
            ck(_rc == 1,
               "engine down AFTER a docroot audited -> hard overall=1, not SKIP: rc=%r" % _rc)
        finally:
            ax._serve_and_audit = _orig_sna
            os.environ.pop("AXE_SOURCE", None)
            os.unlink(_axe_js)

    # axe-ignore: parse skips comments + canonicalises, and a built-tree path matches the audited
    # URL form (so `wiki/Dev/wikitest.html` excludes the page served at /wiki/Dev/wikitest.html).
    ig = ax.parse_axe_ignore("# comment\nwiki/Dev/wikitest.html\n\n  wiki/Foo.html  \n")
    ck(ig == {"wiki/Dev/wikitest", "wiki/Foo"}, "parse_axe_ignore canonicalises + skips comments: %r" % ig)
    ck(ax._canon_path("/wiki/Dev/wikitest.html").lstrip("/") in ig, "audited URL path matches entry")
    # guardrail (dev1324 #18): the SHIPPED wiki ignore-lists exclude EXACTLY the enumerated
    # demo/test fixtures -- a 5th page is a conscious edit (this test reds), never silent growth.
    _expect = {"wiki/Dev/wikitest", "wiki/Dev/website", "wiki/Dev/mediawiki",
               "wiki/TestpageForFlyInNotification"}
    _bdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "axe-baselines")
    for _site in ("kicksecure-wiki-static", "whonix-wiki-static"):
        _got = ax.parse_axe_ignore(
            Path(os.path.join(_bdir, "axe-ignore-%s.txt" % _site)).read_text(encoding="utf-8"))
        ck(_got == _expect, "%s axe-ignore == exactly the 4 enumerated fixtures: %r" % (_site, _got))

    # redirect-stub hermetic skip (_axe_page): a page whose meta-refresh navigates OFF the local
    # mount (a Moved:/redirect stub -> production) must be SKIPPED, not audited -- else axe reports
    # PRODUCTION's live a11y against our stub (the old-MediaWiki ghosts). The route handler aborts
    # the off-mount navigation and records it so _axe_page returns a {"redirect": ...} marker; a
    # same-origin page audits normally (no false redirect).
    import asyncio as _asyncio

    class _FakeRequest:
        def __init__(self, url, frame, nav):
            self.url, self._frame, self._nav = url, frame, nav

        @property
        def frame(self):
            return self._frame

        def is_navigation_request(self):
            return self._nav

    class _FakeRoute:
        def __init__(self, request):
            self.request, self.action = request, None

        async def continue_(self):
            self.action = "continue"

        async def abort(self):
            self.action = "abort"

    class _FakeResponse:
        status = 200

    class _FakePage:
        def __init__(self, offsite, delayed=False):
            self.main_frame = object()
            self._handler: Optional[Callable[[Any], Awaitable[Any]]] = None
            self._offsite = offsite   # None, or a URL a meta-refresh retargets to (any origin)
            self._delayed = delayed   # True = the refresh fires DURING settle, not at load

        async def route(self, _pattern, handler):
            self._handler = handler

        async def _refresh(self):
            assert self._handler is not None
            await self._handler(_FakeRoute(_FakeRequest(self._offsite, self.main_frame, True)))

        async def goto(self, url, **_k):
            assert self._handler is not None   # route() always runs before goto()
            await self._handler(_FakeRoute(_FakeRequest(url, self.main_frame, True)))
            if self._offsite is not None and not self._delayed:   # immediate (content="0") refresh
                await self._refresh()
            return _FakeResponse()

        async def wait_for_timeout(self, _ms):
            if self._offsite is not None and self._delayed:       # delayed (content="N") refresh
                await self._refresh()

        async def evaluate(self, _src):
            return []                      # axe inject, then a clean run

        async def close(self):
            pass

    class _FakeBrowser:
        def __init__(self, offsite, delayed=False):
            self._offsite = offsite
            self._delayed = delayed

        async def new_page(self):
            return _FakePage(self._offsite, self._delayed)

    _local = "http://127.0.0.1:8000/wiki/Stub.html"
    _redir = _asyncio.run(ax._axe_page(
        _FakeBrowser("https://www.kicksecure.com/wiki/Real"), _local, "axe=1", 0))
    ck(_redir.get("redirect") == "https://www.kicksecure.com/wiki/Real",
       "off-mount meta-refresh -> redirect skip, production never audited: %r" % _redir)
    # a SAME-ORIGIN meta-refresh (a Moved:/Dev.html stub -> /wiki/Design) is also a redirect: its
    # target (or a 404 when absent) must not be audited under the stub's path.
    _same = _asyncio.run(ax._axe_page(
        _FakeBrowser("http://127.0.0.1:8000/wiki/Design"), _local, "axe=1", 0))
    ck(_same.get("redirect") == "http://127.0.0.1:8000/wiki/Design",
       "same-origin meta-refresh -> redirect skip, target not audited as the stub: %r" % _same)
    # a DELAYED meta-refresh (content="N") fires DURING the settle window, after the pre-settle
    # redirect check -- the post-settle re-check must still skip it, not audit the stub as a page.
    _delayed = _asyncio.run(ax._axe_page(
        _FakeBrowser("http://127.0.0.1:8000/wiki/Later", delayed=True), _local, "axe=1", 0))
    ck(_delayed.get("redirect") == "http://127.0.0.1:8000/wiki/Later",
       "a meta-refresh firing DURING settle is caught post-settle, not audited: %r" % _delayed)
    _okpage = _asyncio.run(ax._axe_page(_FakeBrowser(None), _local, "axe=1", 0))
    ck("redirect" not in _okpage and _okpage.get("status") == 200,
       "a non-redirecting page audits normally (no false redirect): %r" % _okpage)

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
