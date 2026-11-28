#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.axe's pure (browser-free) engine: target normalization (incl.
the frame/shadow boundary shapes), violation -> (path, rule, target) key mapping, baseline
parse/format roundtrip, and the accept-baseline comparison -- a NEW violation fails, a baselined
one passes, a resolved one is reported, and a MISSING baseline fails CLOSED. Run by the
website-tests launcher (a required unit) or directly: ./check_axe_test.py"""
import contextlib
import inspect
import io
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

    # axe-ignore <-> restrict interaction (CodeRabbit #789 fix-forward r4431457774): an ignored page
    # is in the tree but NOT audited, so its baseline keys must be neither misreported 'resolved'
    # (check) nor discarded (seed), in curated AND full-tree mode. `ignore` is _canon_path.lstrip('/').
    ign = {"wiki/Dev/wikitest"}
    bli = {("/", "x", "a"), ("/wiki/Dev/wikitest", "lk", "img"), ("/wiki/ISO", "cc", "a")}
    # CHECK: full-tree drops only the ignored page's keys (removed-page 'resolved' behaviour kept).
    ck(ax._restrict_baseline(bli, None, ign)
       == {("/", "x", "a"), ("/wiki/ISO", "cc", "a")},
       "_restrict_baseline full-tree drops ignored page keys only")
    # CHECK: curated also drops the ignored page even when the curated list names it.
    ck(ax._restrict_baseline(bli, ["/", "/wiki/Dev/wikitest"], ign) == {("/", "x", "a")},
       "_restrict_baseline curated drops an ignored page named in the restrict list")
    # SEED: full-tree preserves the ignored page's existing keys (not re-audited), replaces the rest.
    exi = {("/", "old", "a"), ("/wiki/Dev/wikitest", "lk", "img")}
    frh = {("/", "new", "c")}
    ck(ax._merge_seed(exi, frh, None, ign)
       == {("/", "new", "c"), ("/wiki/Dev/wikitest", "lk", "img")},
       "_merge_seed full-tree + ignore preserves the ignored page's accepted keys")
    # SEED: curated naming the ignored page still preserves it (would otherwise vanish: in restrict,
    # absent from fresh).
    ck(ax._merge_seed(exi, frh, ["/", "/wiki/Dev/wikitest"], ign)
       == {("/", "new", "c"), ("/wiki/Dev/wikitest", "lk", "img")},
       "_merge_seed curated + ignore preserves the ignored page named in the restrict list")

    # _apply_ignore: the vacuous-audit guard (CodeRabbit #789 fix-forward r4431457699). A curated
    # --paths-file of ONLY ignored pages empties the audit set -> auditing nothing would PASS
    # vacuously against an existing baseline. Refuse with _VacuousAudit.
    ck(ax._apply_ignore(["/", "/wiki/ISO"], None) == (["/", "/wiki/ISO"], 0),
       "_apply_ignore no ignore-set -> request unchanged")
    ck(ax._apply_ignore(["/wiki/Dev/wikitest", "/"], ign) == (["/"], 1),
       "_apply_ignore drops ignored pages, counts them")
    ck(ax._apply_ignore([], ign) == ([], 0),
       "_apply_ignore empty request is not vacuous (empty-restrict guarded elsewhere)")
    try:
        ax._apply_ignore(["/wiki/Dev/wikitest"], ign)
        ck(False, "_apply_ignore raises _VacuousAudit when every requested page is ignored")
    except ax._VacuousAudit:
        ck(True, "_apply_ignore raises _VacuousAudit when every requested page is ignored")

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
                    return (set(), [], 0)       # first docroot: clean audit, 0 excluded
                raise ax._EngineUnavailable("simulated mid-run launch failure")

            ax._serve_and_audit = _sna_second_fails
            _rc = ax.check_roots([_r1, _r2], _bdir)
            ck(_rc == 1,
               "engine down AFTER a docroot audited -> hard overall=1, not SKIP: rc=%r" % _rc)

            # (C) a vacuous-audit FAIL is DURABLE (CodeRabbit/fresh-claude #790 fix-forward): a site
            # whose whole audit set is axe-ignored FAILs (_VacuousAudit); a LATER docroot's engine
            # failure (while audited==0) must NOT _skip(77) and discard that FAIL. First root ->
            # vacuous, second -> engine down -> the run must end rc=1, never SKIP(77).
            _calls_c = {"n": 0}

            def _sna_vacuous_then_engine(*_a, **_k):
                _calls_c["n"] += 1
                if _calls_c["n"] == 1:
                    raise ax._VacuousAudit("all 1 requested path(s) are axe-ignored -- nothing left")
                raise ax._EngineUnavailable("simulated post-vacuous launch failure")

            ax._serve_and_audit = _sna_vacuous_then_engine
            _rc_c = ax.check_roots([_r1, _r2], _bdir)
            ck(_rc_c == 1,
               "a vacuous FAIL is durable: a later engine-unavailable does not mask it as "
               "SKIP(77): rc=%r" % _rc_c)

            # (D) a full re-seed on an ignore-list site must TOLERATE a malformed existing baseline
            # (CodeRabbit/fresh-claude #790 fix-forward): the new 'or ignore' read of the old file
            # must not let parse_baseline's ValueError crash the reseed -- a seed overwrites, so a
            # corrupt existing degrades to 'preserve nothing', never a crash.
            _ign = Path(_bdir, "axe-ignore-%s.txt" % os.path.basename(_r1))
            _ign.write_text("wiki/Dev/wikitest\n", encoding="utf-8")   # ignore truthy -> read path
            _bad = Path(_bdir, "axe-baseline-%s.txt" % os.path.basename(_r1))
            _bad.write_text("justpath\n", encoding="utf-8")            # malformed (parse_baseline reds)
            _fresh_d = {("/wiki/Foo", "color-contrast", "a")}
            ax._serve_and_audit = lambda *_a, **_k: (set(_fresh_d), [], 0)
            try:
                _rc_d = ax.write_roots([_r1], _bdir)   # restrict=None -> FULL re-seed, ignore truthy
                ck(_rc_d == 0, "full re-seed tolerates a malformed existing baseline (rc=%r)" % _rc_d)
                _reseeded = ax.parse_baseline(_bad.read_text(encoding="utf-8"))
                ck(_reseeded == _fresh_d,
                   "re-seed overwrote the corrupt baseline with the fresh set: %r" % (_reseeded,))
            except ValueError as _exc:
                ck(False, "full re-seed crashed on a malformed existing baseline: %r" % _exc)
            finally:
                _ign.unlink(missing_ok=True)
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

    # curated-sample CLASS COVERAGE contract (dev1324 #16/#18): the per-deploy gate is a
    # REPRESENTATIVE subset, so each fixed a11y class must keep a representative page in the curated
    # file. The shipped '# class: <slug>' annotations MUST cover exactly the canonical class set --
    # dropping a representative (losing coverage) or adding an unlisted class REDs this test, so the
    # subset can never silently stop exercising a class the full-tree backstop would still catch.
    _canon_classes = {
        "table-cell-links", "zebra-table", "nested-info-box", "collapsible-code-select",
        "linked-image-gallery", "cs-status-badge", "freelink", "share-menu", "about-box-table",
        "file-page", "content-visibility", "leftrightimagetext", "status-cell", "code-select",
        "redirect-stub", "link-name"}
    _curated = os.path.join(os.path.dirname(os.path.realpath(__file__)), "axe-wiki-curated-paths.txt")
    _lines = Path(_curated).read_text(encoding="utf-8").splitlines()
    _classes = [ln.strip()[len("# class:"):].strip()
                for ln in _lines if ln.strip().startswith("# class:")]
    ck(len(_classes) == len(set(_classes)),
       "curated '# class:' annotations are unique (no duplicate representative): %r" % (_classes,))
    ck(set(_classes) == _canon_classes,
       "curated class representatives cover exactly the canonical set (missing=%r extra=%r)"
       % (sorted(_canon_classes - set(_classes)), sorted(set(_classes) - _canon_classes)))
    # Every annotated class' path is a real root-relative audit path (and _load_paths_file yields a
    # non-empty curated list -- a mangled file that parses to nothing must not read as "covered").
    _paths = ax._load_paths_file(_curated)
    ck(_paths and all(p.startswith("/") for p in _paths),
       "curated paths are all root-relative and the list is non-empty (%d paths)" % len(_paths))
    # Each '# class:' annotation sits directly above a path line (so a representative is a real
    # audited page, not a dangling label).
    _class_targets = [_lines[i + 1].strip() for i, ln in enumerate(_lines)
                      if ln.strip().startswith("# class:") and i + 1 < len(_lines)]
    ck(all(t.startswith("/") for t in _class_targets) and len(_class_targets) == len(_classes),
       "each '# class:' annotation is immediately followed by its representative path")

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
            self.last_viewport = None

        async def new_page(self, viewport=None):
            self.last_viewport = viewport
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

    # mobile-width coverage: the gate audits each page at BOTH a desktop and a narrow viewport, so
    # a target-size (or any wrap-dependent) violation that fires only on a mobile layout is caught,
    # not just desktop. Guard that _VIEWPORTS keeps both widths and that _axe_page forwards one.
    _b = _FakeBrowser(None)
    _asyncio.run(ax._axe_page(_b, _local, "axe=1", 0, {"width": 390, "height": 844}))
    ck(_b.last_viewport == {"width": 390, "height": 844},
       "_axe_page forwards its viewport to new_page: %r" % _b.last_viewport)
    _widths = {vp["width"] for _n, vp in ax._VIEWPORTS}
    ck(390 in _widths and any(w >= 1000 for w in _widths),
       "_VIEWPORTS audits both a mobile (390) and a desktop width: %r" % _widths)

    # _axe_page is exception-safe (CodeRabbit finding 2026-11-27): it owns the page and closes it in a
    # `finally` even when the audit RAISES -- a direct caller that catches the error and keeps the
    # browser must not leak the opened page. (check()'s own path does browser-level cleanup instead and
    # keeps page.close OUTSIDE its budget, so _axe_page must NOT route through _open_and_audit.)
    _closed = {"n": 0}

    class _FakePageErr:
        def __init__(self):
            self.main_frame = object()

        async def route(self, _pattern, _handler):
            pass

        async def goto(self, _url, **_k):
            raise RuntimeError("navigation failed")   # a real load failure (no redirect) -> re-raised

        async def close(self):
            _closed["n"] += 1

    class _FakeBrowserErr:
        async def new_page(self, viewport=None):
            return _FakePageErr()

    try:
        _asyncio.run(ax._axe_page(_FakeBrowserErr(), _local, "axe=1", 0))
        ck(False, "_axe_page propagates a raising audit (did not swallow the error)")
    except RuntimeError:
        ck(_closed["n"] == 1,
           "_axe_page closes the page even when the audit RAISES (no leak): closed=%d" % _closed["n"])

    # RETRY (wedge + audit error) + teardown isolation + mid-run engine resilience (operator decisions
    # 2026-11-27 dev1877 #87, extended 2026-11-28 to retry transient audit ERRORS too; codex / grok /
    # reviewdrain review fixes). check() delegates each (page, viewport) to _retry.audit_with_retry: the
    # single hard wall-clock budget times page creation AND the audit together (_open_and_audit);
    # page.close() runs OUTSIDE it. A WEDGE (asyncio.TimeoutError, a timing fault under concurrent-lane
    # contention, including a wedged new_page) AND a non-timeout audit ERROR (a dead-browser new_page
    # crash, a navigation / axe-evaluation error) are BOTH transient non-completions -> retried on a
    # fresh browser, reported only when EVERY attempt faults (the retry cannot MASK a real failure: a
    # real violation needs a COMPLETED audit, and a deterministic error recurs every attempt). A
    # completed audit returns BEFORE its close, so a slow/failing teardown never discards it; and a
    # mid-run chromium death that cannot relaunch records the remaining pages as audit errors and
    # RETURNS the collected keys (a hard FAIL), never a traceback and never a SKIP(77) that would mask
    # an already-found violation -- only the INITIAL launch failure raises _EngineUnavailable. Drive the
    # REAL check() with _audit_page faked per (page, viewport); the fake async_playwright supplies
    # browsers (pages carry their viewport) and can fail a given launch (relaunch failure) or a given
    # new_page (mid-run browser crash).
    _pw_mod = sys.modules.setdefault("playwright.async_api", _types.ModuleType("playwright.async_api"))

    class _FakePage3:
        def __init__(self, viewport, close_exc):
            self.viewport = viewport
            self._close_exc = close_exc

        async def close(self):
            if self._close_exc is not None:
                raise self._close_exc

    class _FakeBrowser3:
        def __init__(self, state):
            self._state = state

        async def new_page(self, viewport=None):
            self._state["new_pages"] = self._state.get("new_pages", 0) + 1
            if self._state["new_pages"] == self._state.get("new_page_fail_on"):
                # chromium died between pages -> new_page raises (e.g. TargetClosedError).
                raise RuntimeError("TargetClosedError: browser has been closed")
            return _FakePage3(viewport, self._state.get("close_exc"))

        async def close(self):
            pass

    class _FakeChromium3:
        def __init__(self, state):
            self._state = state

        async def launch(self):
            self._state["launches"] += 1
            if self._state["launches"] == self._state.get("launch_fail_on"):
                raise RuntimeError("chromium launch failed: too many open files")
            return _FakeBrowser3(self._state)

    class _FakePW3:
        def __init__(self, state):
            self.chromium = _FakeChromium3(state)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    _WBASE = "http://127.0.0.1:8000"

    def _run_check(paths, wedge_counts=None, hard_timeout=1, error_counts=None,
                   violations=None, close_exc=None, launch_fail_on=None, new_page_fail_on=None):
        # wedge_counts:    {(path,width): N} -- raise TimeoutError (a WEDGE) the first N audit calls for
        #   that (page, viewport), then audit clean. N >= _AUDIT_ATTEMPTS models a REAL double wedge.
        # error_counts:    {(path,width): N} -- raise RuntimeError (a NON-timeout ERROR) the first N.
        # violations:      {(path,width): [axe-violation,...]} -- the clean audit returns these.
        # close_exc:       an exception page.close() raises (teardown failure), else None.
        # launch_fail_on:  the Nth chromium.launch() to fail (models a relaunch failure), else None.
        # new_page_fail_on: the Nth browser.new_page() to raise (models a mid-run browser crash
        #   between pages), else None -- counted GLOBALLY across (re)launched browsers.
        wedge_counts = wedge_counts or {}
        error_counts = error_counts or {}
        violations = violations or {}
        state = {"launches": 0, "new_pages": 0, "close_exc": close_exc,
                 "launch_fail_on": launch_fail_on, "new_page_fail_on": new_page_fail_on}
        seen: dict = {}

        async def _fake_audit_page(page, url, _axe_src, _settle_ms):
            path = url[len(_WBASE):] or "/"
            if not path.startswith("/"):
                path = "/" + path
            key = (path, (page.viewport or {}).get("width"))
            seen[key] = seen.get(key, 0) + 1
            n = seen[key]
            if n <= error_counts.get(key, 0):
                raise RuntimeError("simulated axe-evaluation error")
            if n <= wedge_counts.get(key, 0):
                raise _asyncio.TimeoutError()
            return {"status": 200, "violations": violations.get(key, [])}

        _orig_audit = ax._audit_page
        _orig_apw = getattr(_pw_mod, "async_playwright", None)
        setattr(_pw_mod, "async_playwright", lambda: _FakePW3(state))
        ax._audit_page = _fake_audit_page
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as _js:
            _js.write(b"axe=1")
            _js_name = _js.name
        try:
            keys, problems = _asyncio.run(
                ax.check(_WBASE, list(paths), _js_name, 0, hard_timeout))
        finally:
            ax._audit_page = _orig_audit
            if _orig_apw is None:
                if hasattr(_pw_mod, "async_playwright"):
                    delattr(_pw_mod, "async_playwright")
            else:
                setattr(_pw_mod, "async_playwright", _orig_apw)
            os.unlink(_js_name)
        return keys, problems, state["launches"]

    # at least one retry is configured.
    ck(getattr(ax, "_AUDIT_ATTEMPTS", 1) >= 2,
       "a fault gets at least one retry (_AUDIT_ATTEMPTS >= 2): %r" % getattr(ax, "_AUDIT_ATTEMPTS", 1))
    # a page that wedges ONCE then audits clean is NOT a problem -- the transient flake is absorbed.
    _k1, _p1, _l1 = _run_check(["/"], {("/", 1280): 1})
    ck(_p1 == [],
       "wedge RETRY: a page that wedges once then audits clean is NOT a problem (flake absorbed): %r" % _p1)
    ck(_l1 == 2,
       "wedge RETRY: one wedge triggers exactly one relaunch (1 initial + 1 retry browser): %r" % _l1)
    # masking-safety: a page that wedges on EVERY attempt is STILL reported.
    _k2, _p2, _l2 = _run_check(["/"], {("/", 1280): 99})
    ck(_p2 == ["wedged: / [desktop]"],
       "wedge RETRY: a page wedging on every attempt is STILL reported (retry does not mask it): %r" % _p2)
    # operator decision (2026-11-28): a transient NON-timeout audit ERROR is ALSO retried (dual-lane
    # contention errors withheld a clean deploy). A page that errors ONCE then audits clean is NOT a
    # problem -- the transient fault is absorbed on the fresh-browser retry (was recorded immediately
    # before this decision; the reversal is safe -- see the every-attempt case below).
    _ke, _pe, _le = _run_check(["/"], error_counts={("/", 1280): 1})
    ck(_pe == [],
       "audit-error RETRY: a page that errors once then audits clean is NOT a problem (flake absorbed): %r" % _pe)
    ck(_le == 2,
       "audit-error RETRY: one error triggers exactly one relaunch (1 initial + 1 retry browser): %r" % _le)
    # masking-safety: a page that errors on EVERY attempt is STILL reported (a deterministic error
    # recurs every attempt, so the retry cannot mask a real un-auditable page or a real violation --
    # a violation needs a COMPLETED audit, which an all-errors page never reaches).
    _ke2, _pe2, _le2 = _run_check(["/"], error_counts={("/", 1280): 99})
    ck(_pe2 == ["audit error: / [desktop]"],
       "audit-error RETRY: a page erroring on every attempt is STILL reported (retry does not mask): %r" % _pe2)
    # grok finding (2026-11-27): page.close() is timed SEPARATELY, outside the budget, and the audit
    # returns before it -- so a completed audit whose teardown FAILS keeps its violation (never
    # discarded as a wedge and retried away to empty). Guard the invariant that the TIMED audit itself
    # never closes the page, plus the observable behaviour under a failing close.
    ck(".close(" not in inspect.getsource(ax._audit_page),
       "_audit_page never closes the page (close is outside the timed audit)")
    _viol = [{"id": "color-contrast", "nodes": [{"target": ["a.bad"]}]}]
    _ks, _ps, _ls = _run_check(["/"], violations={("/", 1280): _viol},
                               close_exc=RuntimeError("close failed"))
    ck(("/", "color-contrast", "a.bad") in _ks and _ps == [],
       "a completed audit whose teardown FAILS keeps its violation (close outside the budget): "
       "keys=%r problems=%r" % (sorted(_ks), _ps))
    # codex+grok+reviewdrain finding (2026-11-27): browser.new_page() is a mid-run browser call that
    # can RAISE if chromium dies between pages (TargetClosedError) OR hang. It is now INSIDE the timed,
    # caught region (_open_and_audit), so a crash is a caught audit error -- never an uncaught traceback
    # that aborts the whole gate (and every remaining docroot). Since the 2026-11-28 decision retries a
    # transient audit error too, a ONE-OFF new_page crash is ABSORBED on the fresh-browser retry and the
    # run continues with already-collected keys intact. '/' desktop collects a violation; '/' mobile's
    # new_page (#2) crashes then its retry (new_page #3) audits clean; '/wiki/B' audits clean too.
    _nv = [{"id": "image-alt", "nodes": [{"target": ["img.x"]}]}]
    _kn, _pn, _ln = _run_check(["/", "/wiki/B"], violations={("/", 1280): _nv}, new_page_fail_on=2)
    ck(("/", "image-alt", "img.x") in _kn,
       "a mid-run new_page crash does NOT discard already-collected keys: %r" % sorted(_kn))
    ck(_pn == [],
       "a one-off mid-run new_page crash is ABSORBED on the retry; the run recovers and continues "
       "(no traceback, no recorded problem): %r" % _pn)
    # new_page is bounded + caught STRUCTURALLY: check() creates no page outside the timed region --
    # it delegates each (page, viewport) to the shared helper, which time-boxes _open_and_audit
    # (new_page + audit together), so a wedged new_page is a retryable WEDGE and a crashing one a caught
    # error, never an unbounded hang or an escaping traceback.
    _check_src2 = inspect.getsource(ax.check)
    ck("browser.new_page" not in _check_src2,
       "check() creates no page outside the timed region (new_page lives in _open_and_audit)")
    ck("audit_with_retry" in _check_src2 and "_open_and_audit" in _check_src2,
       "check() delegates per-page auditing to the shared retry helper")
    _retry_src = inspect.getsource(ax.audit_with_retry)
    ck("wait_for" in _retry_src and "open_and_audit" in _retry_src,
       "the shared helper time-boxes page creation + audit together (wait_for over open_and_audit)")

    # codex+coderabbit+claude finding (2026-11-28): the RETRY line (shared helper) and the TIMEOUT /
    # ERROR diagnostics print the (page-derived) label and the exception detail; these lines bypass the
    # baseline, so a control char in a path or exception string could inject a terminal escape (OSC-52
    # clipboard write, erase-screen). Both sinks must strip C0/C1, like _safe_terminal does for every
    # other line. _clip handles the detail; the label is sanitized at each print. Drive a page whose
    # path carries ESC/BEL/erase-screen, erroring on EVERY attempt (exercises the RETRY line AND the
    # final ERROR line), and assert the captured stdout carries no raw control char.
    from dist_ai.webcheck import _retry as _retry_mod
    ck("\x1b" not in _retry_mod._clip("a\x1b]52;c;x\x07b") and "\x07" not in _retry_mod._clip("a\x1b\x07b"),
       "_clip strips C0/C1 control chars from the exception detail")
    _evil = "/\x1b]52;c;SGk\x07\x1b[2J"
    _cap = io.StringIO()
    with contextlib.redirect_stdout(_cap):
        _run_check([_evil], error_counts={(_evil, 1280): 99, (_evil, 390): 99})
    _out = _cap.getvalue()
    ck("\x1b" not in _out and "\x07" not in _out,
       "a control-char page path is stripped from the RETRY + ERROR diagnostics (no escape injection): %r"
       % _out)

    # grok finding (2026-11-27): a mid-run relaunch whose chromium.launch() FAILS must NOT raise
    # _EngineUnavailable out of check() -- reaching check_roots with audited==0 it would become a
    # SKIP(77) that MASKS a violation already collected from an earlier page. Instead the
    # un-relaunchable pages are recorded as hard problems and check() RETURNS its collected keys, so the
    # caller FAILs (never a silent env-unmet SKIP). '/' desktop collects a violation; '/' mobile wedges
    # -> the relaunch (launch #2) fails (recorded with its actual fault kind, wedged); the remaining
    # '/wiki/B' pages are then engine-unavailable audit errors.
    _rv = [{"id": "image-alt", "nodes": [{"target": ["img.y"]}]}]
    _kr, _pr, _lr = _run_check(["/", "/wiki/B"], {("/", 390): 1},
                               violations={("/", 1280): _rv}, launch_fail_on=2)
    ck(("/", "image-alt", "img.y") in _kr,
       "a mid-run relaunch failure does NOT discard already-collected keys (no SKIP mask): %r"
       % sorted(_kr))
    ck(_pr and all(p.startswith(("audit error:", "wedged:")) for p in _pr),
       "a relaunch failure records the un-auditable pages as hard problems (a FAIL), never raising "
       "_EngineUnavailable to be masked as SKIP: %r" % _pr)

    # The INITIAL launch failure (nothing audited yet) is the ONE honest env-unmet case: check() still
    # raises _EngineUnavailable so the caller (check_roots) can SKIP(77). (A mid-run relaunch failure
    # degrades to audit errors instead; see above.)
    try:
        _run_check(["/"], launch_fail_on=1)
        _ri = "none"
    except ax._EngineUnavailable:
        _ri = "engine"
    except Exception as _exc:          # noqa: BLE001
        _ri = type(_exc).__name__
    ck(_ri == "engine",
       "the INITIAL chromium launch failure raises _EngineUnavailable (caller decides SKIP): %r" % _ri)

    # per-page TIMEOUT budget (operator decision 2026-11-27: "retry AND suitable timeout"). A single
    # wall-clock budget is the ONLY timeout authority (page.goto carries no own timeout), so it must
    # be suitably large; and it is the default every entry point audits with.
    ck(ax._HARD_TIMEOUT_DEFAULT >= 90,
       "per-page wall-clock budget is suitably large (>= 90s): %rs" % ax._HARD_TIMEOUT_DEFAULT)
    for _fn in (ax.check, ax.check_roots, ax.write_roots):
        ck(inspect.signature(_fn).parameters["hard_timeout"].default == ax._HARD_TIMEOUT_DEFAULT,
           "%s defaults hard_timeout to _HARD_TIMEOUT_DEFAULT" % _fn.__name__)

    # identical-links-same-purpose (WCAG 2.4.9 AAA) is OFF by default in axe-core; the run options
    # must keep it explicitly enabled, or the gate silently stops catching two same-name links that
    # point at different destinations. Guard the explicit enable against an accidental revert.
    ck("identical-links-same-purpose" in ax._AXE_RUN_JS and "enabled: true" in ax._AXE_RUN_JS,
       "identical-links-same-purpose rule is explicitly enabled in _AXE_RUN_JS")

    # Enabling the rule is necessary but NOT sufficient: axe-core reports it as INCOMPLETE
    # (needs-review), never a violation, so a violations-only run gates nothing (a false green).
    # The run MUST collect 'incomplete' AND promote this rule's entries into the returned set.
    # Guard every link in that chain so a revert to violations-only fails loudly.
    ck("identical-links-same-purpose" in ax._PROMOTE_INCOMPLETE_RULES,
       "identical-links-same-purpose is in the promote-incomplete set")
    ck("'incomplete'" in ax._AXE_RUN_JS,
       "the run collects 'incomplete' results (not violations-only)")
    ck("r.incomplete" in ax._AXE_RUN_JS and ".concat(" in ax._AXE_RUN_JS,
       "promoted incompletes are merged into the returned result set")
    # The promoted entries flow through result_keys exactly like a violation (same {id, nodes:
    # [{target}]} shape), so a same-name/different-dest incomplete becomes a gated key per node.
    _promoted = [{"id": "identical-links-same-purpose",
                  "nodes": [{"target": ["a[href='/x']"]}, {"target": ["a[href='/y']"]}]}]
    ck(set(ax.result_keys("/wiki/About", _promoted)) ==
       {("/wiki/About", "identical-links-same-purpose", "a[href='/x']"),
        ("/wiki/About", "identical-links-same-purpose", "a[href='/y']")},
       "a promoted identical-links incomplete yields one gated key per node")

    # target-size (WCAG 2.5.8 AA) is ALSO OFF by default in axe-core; without the explicit enable
    # the gate silently never checks touch-target size/spacing (undersized footnote markers, inline
    # icon links). Guard the enable against an accidental revert.
    ck("'target-size': {enabled: true}" in ax._AXE_RUN_JS,
       "target-size rule is explicitly enabled in _AXE_RUN_JS")

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
