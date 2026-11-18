#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.forced_reflow's pure (browser-free) logic: forced-event
detection (a Layout/UpdateLayoutTree with a JS stack is forced; without one it is a pipeline
layout), first-party stack attribution (only a frame from the page's own origin counts), the
?h= buster strip in the frame label, URL join, off-origin detection, page enumeration, and the
two required mutually-exclusive argparse groups. Run by the website-tests launcher (a required
unit) or directly: ./check_forced_reflow_test.py"""
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
    ck(forced and forced[0][0] == "app.min.js:168:93 (sync)",
       "frame label is basename:line:col (function), ?h= buster stripped")

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

    # --- is_first_party / is_off_origin (host identity) ---
    ck(fr.is_first_party(BASE + "/a.js", BASE) is True, "same-host frame is first-party")
    ck(fr.is_first_party("https://evil.test/a.js", BASE) is False, "other-host frame is not")
    ck(fr.is_first_party("", BASE) is False, "a url-less (native) frame is not first-party")
    ck(fr.is_off_origin("http://127.0.0.1:8099/wiki/X", BASE) is False, "same host -> not off-origin")
    ck(fr.is_off_origin("https://moved.example/", BASE) is True, "other host -> off-origin")

    # --- page_url join ---
    ck(fr.page_url("http://h", "/wiki/A") == "http://h/wiki/A", "page_url joins a rooted path")
    ck(fr.page_url("http://h/", "wiki/A") == "http://h/wiki/A", "page_url tolerates a bare path")

    # --- enumerate_paths over a built tree ---
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        (tree / "index.html").write_text("x")
        (tree / "wiki").mkdir()
        (tree / "wiki" / "About.html").write_text("x")
        (tree / "wiki" / "Dev").mkdir()
        (tree / "wiki" / "Dev" / "wikitest.html").write_text("x")
        paths = fr.enumerate_paths(tree)
    ck("/" in paths and "/wiki/About" in paths and "/wiki/Dev/wikitest" in paths,
       "enumerate_paths finds root + flat extensionless wiki pages (recursive)")

    # --- argparse: each required mutually-exclusive group is enforced ---
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
            ck(False, label)
        except SystemExit:
            ck(True, label)

    # --- terminal safety: untrusted path/frame/exception text is stripped of control bytes ---
    ck(fr.safe_terminal("a\x1b]52;c;SGFja2Vk\x07b") == "a?]52;c;SGFja2Vk?b",
       "safe_terminal strips the ESC + BEL of an OSC-52 clipboard-write")
    ck("\n" not in fr.safe_terminal("ok\n/evil"),
       "safe_terminal strips newline so a crafted path cannot forge a second output line")
    ck(fr.safe_terminal("/wiki/Normal_Page") == "/wiki/Normal_Page",
       "safe_terminal leaves ordinary printable text untouched")

    # --- baseline: stable key drops line:col, keeps script + function ---
    ck(fr._stable_frame("app.min.js:168:93 (sync)") == "app.min.js (sync)",
       "_stable_frame drops :line:col, keeps script + function")
    ck(fr._stable_frame("mockup.js:47:3 ((anonymous))") == "mockup.js ((anonymous))",
       "_stable_frame handles an anonymous frame")
    ck(fr.baseline_key("/chat-view/", "mockup.js:47:3 (atBottom)")
       == "/chat-view/\tmockup.js (atBottom)",
       "baseline_key joins path + stable frame with a tab")
    ck(fr.baseline_key("/a/", "x.js:1:1 (f)") != fr.baseline_key("/b/", "x.js:1:1 (f)"),
       "same frame on two pages is two distinct keys")
    ck(fr.baseline_key("/a/", "x.js:1:1 (f)") == fr.baseline_key("/a/", "x.js:9:9 (f)"),
       "a line shift does not change the key (stable across unrelated edits)")

    # --- baseline: file round-trip, missing-file, comment/blank handling ---
    with tempfile.TemporaryDirectory() as d:
        bp = Path(d) / "secure-terminal.github.io.txt"
        keys = {"/chat-view/\tmockup.js (atBottom)", "/paste/\tcopy.js (onClick)"}
        fr.write_baseline(bp, keys)
        ck(fr.load_baseline(bp) == frozenset(keys), "write_baseline/load_baseline round-trips keys")
        ck(all(not k.startswith("#") for k in fr.load_baseline(bp)),
           "load_baseline drops the header comment lines")
        ck(fr.load_baseline(Path(d) / "absent.txt") == frozenset(),
           "a missing baseline file means no accepted findings")
        bp.write_text("# just a comment\n\n   \n/x/\ta.js (f)\n")
        ck(fr.load_baseline(bp) == frozenset({"/x/\ta.js (f)"}),
           "load_baseline ignores comment + blank lines")

    sys.stdout.write(
        f"check_forced_reflow_test: {stats['pass']} pass, {stats['fail']} fail, 0 skip\n")
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
