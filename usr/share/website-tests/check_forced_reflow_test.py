#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.forced_reflow's pure (browser-free) logic: forced-event
detection (a Layout/UpdateLayoutTree with a JS stack is forced; without one it is a pipeline
layout), first-party stack attribution (only a frame from the page's own origin counts), the
full-URL-path frame label with its ?h= buster stripped, URL join, off-origin detection, page
enumeration (filesystem names percent-encoded into URL paths), the post-settle verdict
(classify_probe: same-host error validation, off-host redirect still gating pre-redirect forced
layouts, fail-closed on a lossy/incomplete trace), the engine-absent-vs-launch-failure classifier,
the empty-page-list rejection, and the two required mutually-exclusive argparse groups. Run by the
website-tests launcher (a required unit) or directly: ./check_forced_reflow_test.py"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _load():
    # the forced-reflow gate lives in the importable core; import it (its real home).
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import forced_reflow
    return forced_reflow


fr = _load()

BASE = "http://127.0.0.1:8099"
# A stack frame served from the page's own origin (what a forced read's trigger looks like).
OURS = {"url": BASE + "/app.min.js?h=abc123", "lineNumber": 168, "columnNumber": 93,
        "functionName": "sync"}
THIRD = {"url": "https://cdn.example.com/x.js", "lineNumber": 1, "columnNumber": 1,
         "functionName": "ext"}
NATIVE = {"url": "", "lineNumber": 0, "columnNumber": 0, "functionName": ""}

# A completed, lossless trace -- the only state classify_probe may read as a pass.
TRACE_OK = {"loss": False, "done": True}


def _layout(stack=None):
    """A 'Layout' trace event; with a stackTrace under beginData it is FORCED."""
    args = {"beginData": {}}
    if stack is not None:
        args["beginData"]["stackTrace"] = stack
    return {"name": "Layout", "dur": 3300, "args": args}


def _update_layout_tree(stack):
    """An 'UpdateLayoutTree' event carries its stack directly under args.stackTrace."""
    return {"name": "UpdateLayoutTree", "dur": 1200, "args": {"stackTrace": stack}}


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            f"check_forced_reflow_test: {status} {label}\n")

    # --- forced-event detection + first-party attribution (the heart of the gate) ---
    forced = fr.attribute_forced_layouts([_layout([OURS])], BASE)
    ck(len(forced) == 1 and abs(forced[0][1] - 3.3) < 1e-6,
       "a Layout with a first-party stack is a forced reflow (dur in ms)")
    ck(forced and forced[0][0] == "/app.min.js:168:93 (sync)",
       "frame label is the full URL path:line:col (function), ?h= buster stripped")

    ck(fr.attribute_forced_layouts([_layout(None)], BASE) == [],
       "a Layout WITHOUT a JS stack is a pipeline layout, not counted")
    ck(fr.attribute_forced_layouts([_layout([THIRD])], BASE) == [],
       "a forced layout from a THIRD-PARTY frame is not first-party, not counted")
    ck(fr.attribute_forced_layouts([_layout([NATIVE])], BASE) == [],
       "a forced layout with only native frames is not attributed")
    # a native frame on top, a first-party frame below -> attributed to the first-party frame
    ck(len(fr.attribute_forced_layouts([_layout([NATIVE, OURS])], BASE)) == 1,
       "skips a leading url-less frame to the first script frame")
    # UpdateLayoutTree (forced style recalc) counts too, via args.stackTrace
    ck(len(fr.attribute_forced_layouts([_update_layout_tree([OURS])], BASE)) == 1,
       "a forced UpdateLayoutTree (style recalc) with a first-party stack is counted")
    # a non-layout event is ignored
    ck(fr.attribute_forced_layouts([{"name": "Paint", "args": {}}], BASE) == [],
       "a non-layout trace event is ignored")

    # --- frame label keeps the SCRIPT PATH, so same-basename scripts stay distinct ---
    a = fr._frame_label({"url": BASE + "/assets/checkout/ui.js?h=1",
                         "lineNumber": 5, "columnNumber": 1, "functionName": "sync"})
    b = fr._frame_label({"url": BASE + "/assets/search/ui.js?h=2",
                         "lineNumber": 5, "columnNumber": 1, "functionName": "sync"})
    ck(a == "/assets/checkout/ui.js:5:1 (sync)" and a != b,
       "two same-basename scripts under different dirs get DISTINCT labels (path kept)")

    # --- is_first_party / is_off_origin (host identity) ---
    ck(fr.is_first_party(BASE + "/a.js", BASE) is True, "same-host frame is first-party")
    ck(fr.is_first_party("https://evil.test/a.js", BASE) is False, "other-host frame is not")
    ck(fr.is_first_party("", BASE) is False, "a url-less (native) frame is not first-party")
    ck(fr.is_off_origin("http://127.0.0.1:8099/wiki/X", BASE) is False, "same host -> not off-origin")
    ck(fr.is_off_origin("https://moved.example/", BASE) is True, "other host -> off-origin")

    # --- page_url join ---
    ck(fr.page_url("http://h", "/wiki/A") == "http://h/wiki/A", "page_url joins a rooted path")
    ck(fr.page_url("http://h/", "wiki/A") == "http://h/wiki/A", "page_url tolerates a bare path")

    # --- enumerate_paths over a built tree (filesystem names percent-encoded) ---
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        (tree / "index.html").write_text("x")
        (tree / "wiki").mkdir()
        (tree / "wiki" / "About.html").write_text("x")
        (tree / "wiki" / "Dev").mkdir()
        (tree / "wiki" / "Dev" / "wikitest.html").write_text("x")
        # a title whose name would become a URL fragment / needs escaping
        (tree / "wiki" / "Example#Notes.html").write_text("x")
        (tree / "wiki" / "A B.html").write_text("x")
        paths = fr.enumerate_paths(tree)
    ck("/" in paths and "/wiki/About" in paths and "/wiki/Dev/wikitest" in paths,
       "enumerate_paths finds root + flat extensionless wiki pages (recursive)")
    ck("/wiki/Example%23Notes" in paths,
       "enumerate_paths percent-encodes '#' so it cannot become a URL fragment (wrong-page pass)")
    ck("/wiki/A%20B" in paths and all("/" in p or p == "/" for p in paths),
       "enumerate_paths percent-encodes a space while preserving '/' separators")

    # --- classify_probe: the post-settle PASS/FAIL verdict (fail-closed + redirect handling) ---
    ev = [_layout([OURS])]
    r = fr.classify_probe(ev, BASE, 200, BASE + "/", 200, TRACE_OK)
    ck(r.get("forced") and abs(r["ms"] - 3.3) < 1e-6 and "bad_status" not in r,
       "classify_probe: a clean same-host page reports its forced layouts")
    ck(fr.classify_probe([], BASE, 200, BASE + "/", 404, TRACE_OK) == {"bad_status": 404},
       "classify_probe: a 200 that redirects to a same-host 404 during settle FAILS (quiet-404)")
    ck(fr.classify_probe([], BASE, 200, BASE + "/", None, TRACE_OK).get("forced") == [],
       "classify_probe: no post-load navigation -> judged on the initial status (clean)")
    off = fr.classify_probe(ev, BASE, 200, "https://moved.example/", None, TRACE_OK)
    ck(off.get("external") == "https://moved.example/" and len(off.get("forced") or []) == 1,
       "classify_probe: an off-host redirect still carries the pre-redirect first-party forced layout")
    ck(fr.classify_probe([], BASE, 200, "https://moved.example/", None, TRACE_OK).get("forced") == [],
       "classify_probe: a pure off-host redirect (no first-party forced) is external only")
    ck(fr.classify_probe(ev, BASE, 200, BASE + "/", 200, {"loss": True, "done": True})
       == {"trace_bad": "data loss"},
       "classify_probe: a lossy trace fails CLOSED (never read as a within-budget pass)")
    ck(fr.classify_probe(ev, BASE, 200, BASE + "/", 200, {"loss": False, "done": False})
       == {"trace_bad": "tracingComplete never arrived"},
       "classify_probe: an incomplete trace (no tracingComplete) fails CLOSED")
    # A failed navigation leaves Chromium on chrome-error://; that URL is off-host, so it must NOT be
    # read as a benign off-site redirect -- fail CLOSED on the triggering status instead.
    ck(fr.classify_probe([], BASE, 200, "chrome-error://chromewebdata/", 404, TRACE_OK)
       == {"bad_status": 404},
       "classify_probe: a redirect that ends on Chromium's error page FAILS (not a benign external)")
    ck(fr.classify_probe([], BASE, 200, "chrome-error://chromewebdata/", None, TRACE_OK)
       == {"bad_status": 200},
       "classify_probe: a chrome-error end with no post-load status falls back to the initial status")

    # --- engine-absent vs launch-failure: only a missing engine is a SKIP ---
    ck(fr._is_engine_absent(Exception("Executable doesn't exist at /ms-playwright/chrome")) is True,
       "_is_engine_absent: a missing chromium executable is an absent-engine SKIP (77)")
    ck(fr._is_engine_absent(Exception("Timeout 30000ms exceeded.")) is False,
       "_is_engine_absent: a launch TIMEOUT is a real failure, not an absent-engine SKIP")
    ck(fr._is_engine_absent(Exception("Failed to create a sandbox: namespace unavailable")) is False,
       "_is_engine_absent: a sandbox/namespace launch error is a real failure, not a SKIP")
    # "playwright install-deps" (install OS LIBRARIES; chromium IS present) contains the substring
    # "playwright install" -- it must NOT be misread as an absent engine, or a broken-but-installed
    # environment SKIPs (77) instead of failing the gate.
    ck(fr._is_engine_absent(Exception(
        "Host system is missing dependencies to run browsers.\nrun: sudo playwright install-deps")) is False,
       "_is_engine_absent: a missing-OS-libraries error (install-deps) is a real failure, not a SKIP")
    # A genuine missing-executable whose configured path happens to contain 'install-deps' is STILL
    # an absent engine (the definitive message wins before the install-deps exclusion).
    ck(fr._is_engine_absent(Exception("Executable doesn't exist at /tmp/install-deps/chrome")) is True,
       "_is_engine_absent: 'executable doesn't exist' wins even when the path contains install-deps")

    # --- WEBCHECK_SERVE_READY_TIMEOUT parsing: non-finite / non-positive / garbage -> safe default ---
    ck(fr._ready_timeout("5") == 5.0 and fr._ready_timeout("2.5") == 2.5,
       "_ready_timeout: a positive numeric value is used as-is")
    ck(all(fr._ready_timeout(v) == 10.0 for v in ("inf", "nan", "-1", "0", "abc", None, "1e20", "1e11")),
       "_ready_timeout: inf/nan/non-positive/over-TIMEOUT_MAX/garbage/None fall back to the default")
    # Boundary: Event.wait() overflows C time_t above threading.TIMEOUT_MAX, so cap there.
    import threading as _th
    ck(fr._ready_timeout(str(_th.TIMEOUT_MAX)) == _th.TIMEOUT_MAX
       and fr._ready_timeout(str(_th.TIMEOUT_MAX + 1e6)) == 10.0,
       "_ready_timeout: TIMEOUT_MAX is accepted, just above it falls back (no Event.wait overflow)")

    # --- empty page list is rejected, not a zero-page PASS (browser-free: guard precedes launch) ---
    ck(asyncio.run(fr.check(BASE, [])) == 1,
       "check(): an empty page list FAILS (an HTML-less site must not pass as zero pages gated)")

    # --- _serve_tree readiness: bounded wait + announced-port verification (no browser) ---
    def _serve_raises(body, label):
        # Drive _serve_tree against a fake WEBCHECK_SERVE helper; a short ready-timeout keeps it fast.
        # It MUST raise (never hang) and return within the bound -- a hang here fails the whole suite.
        import time as _time
        with tempfile.TemporaryDirectory() as td:
            helper = Path(td) / "fake-serve.py"
            helper.write_text(body, encoding="utf-8")
            old = {k: os.environ.get(k) for k in ("WEBCHECK_SERVE", "WEBCHECK_SERVE_READY_TIMEOUT")}
            os.environ["WEBCHECK_SERVE"] = str(helper)
            os.environ["WEBCHECK_SERVE_READY_TIMEOUT"] = "1.5"
            t0 = _time.time()
            try:
                fr._serve_tree(Path(td))
                raised = False
            except RuntimeError:
                raised = True
            finally:
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            ck(raised and (_time.time() - t0) < 8, label)
    # A: a server that binds-but-never-announces (version skew / stderr-only) must not let a blocking
    # read defeat the deadline -- _serve_tree raises within the bound instead of hanging forever.
    _serve_raises("import time\ntime.sleep(60)\n",
                  "_serve_tree: a child that never announces readiness FAILS within the deadline (no hang)")
    # B: an announced port the child never bound must be rejected, not trusted -- else the gate would
    # measure whatever unrelated service holds that port.
    _serve_raises("import sys, time\nsys.stdout.write('PRE_DEPLOY_SERVE_READY 1\\n')\n"
                  "sys.stdout.flush()\ntime.sleep(60)\n",
                  "_serve_tree: an announced port with nothing listening is rejected (not measured)")
    # C: a line that matches the prefix but carries a non-numeric port must NOT be read as readiness
    # (it would raise a false 'exited' error and orphan the still-running child). It is ignored, so
    # the deadline fires -- raising within the bound, with the child reaped.
    _serve_raises("import sys, time\nsys.stdout.write('PRE_DEPLOY_SERVE_READY nope\\n')\n"
                  "sys.stdout.flush()\ntime.sleep(60)\n",
                  "_serve_tree: a garbage readiness line is ignored, not a false 'exited' (child reaped)")

    # --- argparse: each required mutually-exclusive group is enforced WITH a usage-error exit ---
    for argv, label in [
        ([], "no origin + no page-source errors"),
        (["--base", "http://h"], "no page-source errors"),
        (["--paths", "/"], "no origin errors"),
        (["--base", "http://h", "--serve-tree", ".", "--paths", "/"], "two origins error"),
        (["--base", "http://h", "--paths", "/", "--enumerate-from", "."],
         "two page-sources error"),
    ]:
        try:
            fr.build_parser().parse_args(argv)
            ck(False, label + " (parsed instead of exiting)")
        except SystemExit as e:
            # argparse exits 2 on a usage error; a 0 (or any non-2) exit would wrongly pass a test
            # that is meant to assert REJECTION, so require the usage-error status explicitly.
            ck(e.code == 2, label + " (exits with the usage-error status 2)")

    # --- terminal safety: untrusted path/frame/exception text is stripped of control bytes ---
    ck(fr.safe_terminal("a\x1b]52;c;SGFja2Vk\x07b") == "a?]52;c;SGFja2Vk?b",
       "safe_terminal strips the ESC + BEL of an OSC-52 clipboard-write")
    ck("\n" not in fr.safe_terminal("ok\n/evil"),
       "safe_terminal strips newline so a crafted path cannot forge a second output line")
    ck(fr.safe_terminal("/wiki/Normal_Page") == "/wiki/Normal_Page",
       "safe_terminal leaves ordinary printable text untouched")

    sys.stdout.write(
        f"check_forced_reflow_test: {stats['pass']} pass, {stats['fail']} fail, 0 skip\n")
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
