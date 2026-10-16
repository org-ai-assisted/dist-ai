#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.console's pure (browser-free) logic: benign-noise
allowlisting (fail-closed when empty; suppresses a matched pattern), URL join, off-origin
detection, CSP-violation formatting, page enumeration, retry clamp, and the required
mutually-exclusive page-source argparse group. Run by the website-tests launcher (a required
unit) or directly: ./check_console_test.py"""
import inspect
import os
import re
import sys
import tempfile
from pathlib import Path


def _load():
    # the console gate lives in the importable core; import it (its real home).
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import console
    return console


cce = _load()


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            f"check_console_test: {status} {label}\n")

    # is_allowlisted: fail-CLOSED with the shipped (empty) allowlist -- every hit counts, so a
    # real console error can never be silently swallowed. Then prove a documented pattern DOES
    # suppress its match (and only its match), so the suppression path has real coverage
    # (0-fail != 0-coverage): temporarily install a pattern and restore.
    ck(cce._BENIGN_ALLOWLIST == [], "allowlist ships empty (fail-closed)")
    ck(cce.is_allowlisted("Refused to load the script 'https://cdn.example.com/x.js'") is False,
       "empty allowlist suppresses nothing")
    saved = list(cce._BENIGN_ALLOWLIST)
    cce._BENIGN_ALLOWLIST.append(re.compile(r"benign-widget probe"))
    try:
        ck(cce.is_allowlisted("benign-widget probe fired") is True, "allowlist suppresses match")
        ck(cce.is_allowlisted("a genuine TypeError in app.js") is False,
           "allowlist does NOT suppress a non-match")
    finally:
        cce._BENIGN_ALLOWLIST[:] = saved
    ck(cce._BENIGN_ALLOWLIST == [], "allowlist restored after test")

    # page_url: a path missing its leading slash must still produce a loadable URL (else
    # base+path -> http://hostwiki/... which Playwright mis-reports as a wedge). Idempotent for
    # already-rooted paths and the bare root.
    ck(cce.page_url("https://x", "/wiki/ISO") == "https://x/wiki/ISO", "page_url rooted path")
    ck(cce.page_url("https://x/", "wiki/ISO") == "https://x/wiki/ISO",
       "page_url missing-slash normalized")
    ck(cce.page_url("https://x", "/") == "https://x/", "page_url root")

    # is_off_origin: same HOST -> gate it; a different host -> external, report.
    canonical = "https://kicksecure-stage.github.io"
    for final, base, want in [
        ("https://kicksecure-stage.github.io/wiki/ISO", canonical, False),
        ("https://www.kicksecure.com/wiki/Security_Roadmap", canonical, True),
        ("https://www.whonix.org/wiki/X", canonical, True),
        # same host, scheme upgrade (GitHub Pages http->https 301) -> still OURS, gate it
        ("http://kicksecure-stage.github.io/x", canonical, False),
        # fail-open regressions: Chromium lowercases the host and drops a default port in
        # page.url, so a NON-canonical base must still match its canonical page.url -- else
        # every page reads off-origin and the gate silently skips all checks.
        ("https://kicksecure-stage.github.io/wiki/ISO",
         "https://Kicksecure-Stage.github.io", False),             # base host case
        ("https://kicksecure-stage.github.io/",
         "https://kicksecure-stage.github.io:443", False),         # base explicit default port
        # a malformed base port must NOT raise (host-only compare never reads .port)
        ("https://kicksecure-stage.github.io/",
         "https://kicksecure-stage.github.io:bogus", False),
    ]:
        ck(cce.is_off_origin(final, base) == want, f"is_off_origin({final}, {base})")

    # format_csp: an actionable one-liner; the source location is appended only when present.
    ck(cce.format_csp({"directive": "script-src", "blockedURI": "inline"})
       == "script-src blocked inline", "format_csp no source")
    ck(cce.format_csp({"directive": "script-src", "blockedURI": "inline",
                       "sourceFile": "https://x/wiki/ISO", "line": 12})
       == "script-src blocked inline @ https://x/wiki/ISO:12", "format_csp with source")

    # classify_hits: every console error, pageerror, and CSP violation becomes a (kind, detail)
    # hit; a clean page yields none; an allowlisted message is dropped (canary both directions).
    clean = cce.classify_hits({"console": [], "pageerror": [], "csp": []})
    ck(clean == [], "classify_hits clean -> no hits")
    dirty = cce.classify_hits({
        "console": ["TypeError: x is not a function"],
        "pageerror": ["Error: boom"],
        "csp": [{"directive": "script-src", "blockedURI": "inline"}]})
    ck({k for k, _ in dirty} == {"console", "pageerror", "csp"} and len(dirty) == 3,
       f"classify_hits dirty -> 3 hits across kinds: {dirty}")
    saved = list(cce._BENIGN_ALLOWLIST)
    cce._BENIGN_ALLOWLIST.append(re.compile(r"x is not a function"))
    try:
        filtered = cce.classify_hits({"console": ["TypeError: x is not a function"],
                                      "pageerror": [], "csp": []})
        ck(filtered == [], "classify_hits drops an allowlisted console error")
    finally:
        cce._BENIGN_ALLOWLIST[:] = saved

    # enumerate_paths: FLAT tree -- root index.html + every wiki/<...>.html as an extensionless
    # /wiki/<...> (no .html, no trailing slash, matching the served tree); nested titles recurse;
    # a tree with no root index omits "/".
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        (tree / "index.html").write_text("")
        (tree / "wiki" / "Dev").mkdir(parents=True)
        (tree / "wiki" / "Donate").mkdir(parents=True)
        (tree / "wiki" / "A.html").write_text("")
        (tree / "wiki" / "Dev" / "wikitest.html").write_text("")
        (tree / "wiki" / "Donate" / "PayPal.html").write_text("")
        got = cce.enumerate_paths(tree)
        ck(set(got) == {"/", "/wiki/A", "/wiki/Dev/wikitest", "/wiki/Donate/PayPal"},
           f"enumerate_paths flat nested: {got}")
    with tempfile.TemporaryDirectory() as d:
        tree = Path(d)
        (tree / "wiki").mkdir()
        (tree / "wiki" / "Solo.html").write_text("")
        ck(cce.enumerate_paths(tree) == ["/wiki/Solo"], "enumerate_paths no root index (flat)")

    # check() threads settle + hard_timeout + retries through (a browserless guard the
    # signature exists, and the retries default is >0 so transient-blip resistance is on).
    ck("settle_ms" in inspect.signature(cce.check).parameters, "check() takes settle_ms")
    ck("hard_timeout" in inspect.signature(cce.check).parameters, "check() takes hard_timeout")
    ck(inspect.signature(cce.check).parameters["retries"].default == 2,
       "check() retries defaults to 2")
    ck(cce.build_parser().parse_args(["--base", "https://x", "--paths", "/"]).retries == 2,
       "--retries defaults to 2")
    ck(cce.build_parser().parse_args(
        ["--base", "https://x", "--paths", "/", "--retries", "0"]).retries == 0,
       "--retries 0 parses (disables)")
    # attempts_for: argparse has no minimum on --retries, so a NEGATIVE value must still clamp to
    # at least ONE probe -- range(1, retries+1) would otherwise be empty and report every page
    # "ok" without ever loading it (a fail-open). 0 -> 1 attempt; N -> N+1.
    ck(cce.attempts_for(-1) == 1, "attempts_for(-1) clamps to 1 (no zero-probe loop)")
    ck(cce.attempts_for(-100) == 1, "attempts_for(-100) clamps to 1")
    ck(cce.attempts_for(0) == 1, "attempts_for(0) -> 1 attempt")
    ck(cce.attempts_for(2) == 3, "attempts_for(2) -> 3 attempts")

    # check_roots exists as the family (local-serve) entry.
    ck(callable(getattr(cce, "check_roots", None)), "check_roots family entry present")

    # Page-source modes are mutually exclusive + exactly one required: two modes no longer
    # silently drop one, and none errors instead of a surprise empty run.
    parsed = cce.build_parser().parse_args(["--base", "https://x", "--paths", "/"])
    ck(parsed.paths == ["/"], "--paths parses")
    for argv, label in [
        (["--base", "https://x"], "no page-source errors"),
        (["--base", "https://x", "--paths", "/", "--enumerate-from", "."], "two page-sources error"),
    ]:
        try:
            cce.build_parser().parse_args(argv)
            ck(False, label)
        except SystemExit:
            ck(True, label)

    sys.stdout.write(
        f"check_console_test: {stats['pass']} pass, {stats['fail']} fail, 0 skip\n")
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
