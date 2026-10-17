#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.extlinks' pure (no-network) logic: external-URL collection
(only absolute http(s), fragment stripped, de-duplicated across pages), own-host detection,
and baseline parse/format roundtrip. The network probe (check_url) is not unit-tested here --
it is exercised by the real periodic/CI run. Run by the launcher or: ./check_extlinks_test.py"""
import os
import sys
import tempfile
from pathlib import Path


def _load():
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import extlinks
    return extlinks


el = _load()


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write("check_extlinks_test: %s %s\n" % (status, label))

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "index.html").write_text(
            '<a href="https://example.test/cite">c</a>'
            '<a href="https://example.test/cite#frag">same after frag strip</a>'
            '<img src="http://img.test/x.png">'
            '<a href="/internal">internal, ignored</a>'
            '<a href="mailto:x@y.z">mailto ignored</a>'
            '<a href="#anchor">anchor ignored</a>', encoding="utf-8")
        (root / "sub").mkdir()
        (root / "sub" / "p.html").write_text(
            '<a href="https://example.test/cite">dup across pages</a>'
            '<a href="https://other.test/">o</a>', encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "evil.html").write_text(
            '<a href="https://should-not.test/">git ignored</a>', encoding="utf-8")
        urls = el.collect_external_links(str(root))
        ck(urls == {"https://example.test/cite", "http://img.test/x.png",
                    "https://other.test/"},
           "collects absolute http(s) only, frag stripped, de-duped, .git/internal/mailto/anchor out: %r"
           % sorted(urls))

    # own-host detection (family cross-links).
    ck(el.is_own_host("https://output-lies.github.io/x", {"output-lies.github.io"}),
       "own-host detected")
    ck(not el.is_own_host("https://example.test/x", {"output-lies.github.io"}),
       "third-party host not own")

    # baseline parse/format roundtrip (sorted, comments skipped).
    accepted = {"https://dead.test/a", "https://dead.test/b"}
    text = el.format_baseline(accepted, site="demo")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "b.txt"
        p.write_text(text, encoding="utf-8")
        ck(el.parse_baseline(p) == accepted, "baseline parse/format roundtrip")
        p.write_text("# only a comment\n\n", encoding="utf-8")
        ck(el.parse_baseline(p) == set(), "comment/blank-only baseline -> empty set")

    # a MALFORMED URL must fail THIS url, never crash the gate (urlopen raises ValueError /
    # http.client.InvalidURL / HTTPException, none a URLError/OSError subclass -- the probe
    # catches broadly). No network: a hostless "http://" raises before any connection.
    res = el.check_url("http://", timeout=2)
    ck(isinstance(res, tuple) and res[0] is False,
       "malformed URL returns (False, reason), does not raise: %r" % (res,))

    # a non-http(s) scheme must be refused at the probe boundary (never reaches urlopen -- the
    # B310 file:// / custom-scheme / SSRF guard). No network: the scheme check short-circuits.
    for bad_scheme in ("file:///etc/passwd", "ftp://host/x", "gopher://host"):
        ok, detail = el.check_url(bad_scheme, timeout=2)
        ck(ok is False and "scheme" in detail,
           "non-http(s) scheme refused before urlopen: %r -> %r" % (bad_scheme, detail))

    # a REDIRECT to a non-http(s) target must also be refused (urllib follows redirects; its stock
    # handler permits http(s)->ftp). Drive the handler directly: an ftp target raises HTTPError
    # (stops the hop before the opener touches it); an http(s) target delegates to the stdlib and
    # yields a new Request. No network.
    import io
    import urllib.error
    import urllib.request
    from email.message import Message
    handler = el._SchemeRestrictedRedirectHandler()
    origin = urllib.request.Request("https://origin.test/")
    try:
        handler.redirect_request(origin, io.BytesIO(b""), 302, "Found", Message(),
                                 "ftp://evil.test/x")
        ck(False, "redirect to ftp:// should raise, did not")
    except urllib.error.HTTPError:
        ck(True, "redirect to ftp:// is refused (HTTPError)")
    nxt = handler.redirect_request(origin, io.BytesIO(b""), 302, "Found", Message(),
                                   "https://ok.test/next")
    ck(isinstance(nxt, urllib.request.Request),
       "redirect to https:// is allowed (delegates to stdlib)")

    sys.stdout.write("check_extlinks_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
