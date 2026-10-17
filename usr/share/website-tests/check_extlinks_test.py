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
from urllib.parse import urlsplit


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

    # share-BUTTON exclusion is ALWAYS on (no flag) and PRECISE: a share-platform host whose
    # query embeds the shared page is dropped, but a REAL citation to the same host (a profile,
    # a thread -- no share query) is KEPT. Host checks use urlsplit().hostname EQUALITY, the
    # CodeQL-documented secure form, never a `"host" in url` substring.
    def _has_host(urls, host):
        return any(urlsplit(u).hostname == host for u in urls)

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "index.html").write_text(
            # real share buttons observed on the wiki (query embeds the shared page):
            '<a href="https://facebook.com/sharer.php?u=https%3A%2F%2Fx%2F">share fb</a>'
            '<a href="https://news.ycombinator.com/submitlink?u=https%3A%2F%2Fx%2F&t=T">hn</a>'
            '<a href="https://fosstodon.org/share?text=T%20https%3A%2F%2Fx%2F">toot</a>'
            # real citations to the SAME platforms (no share query) -- must be KEPT:
            '<a href="https://fosstodon.org/@kicksecure">project mastodon</a>'
            '<a href="https://www.reddit.com/r/privacy/comments/abc/thread">cited thread</a>'
            # ordinary citation with a meaningful ?query -- kept, query preserved:
            '<a href="https://ok.test/p?v=1">q1</a>'
            '<a href="https://ok.test/p?v=2">q2</a>', encoding="utf-8")
        links = el.collect_external_links(str(root))
        ck(not any(el._is_share_button(urlsplit(u)) for u in links),
           "no share-button permalink survives collection: %r" % sorted(links))
        ck(_has_host(links, "fosstodon.org") and "https://fosstodon.org/@kicksecure" in links,
           "a REAL citation to a share platform (no share query) is KEPT: %r" % sorted(links))
        ck("https://www.reddit.com/r/privacy/comments/abc/thread" in links,
           "a real reddit THREAD is kept, not dropped as a share button: %r" % sorted(links))
        ck("https://ok.test/p?v=1" in links and "https://ok.test/p?v=2" in links,
           "distinct ?query citations both kept (no false-green collapse): %r" % sorted(links))
    # unit: _is_share_button discriminates button (share query) from citation (no share query).
    from urllib.parse import urlsplit as _us
    ck(el._is_share_button(_us("https://facebook.com/sharer.php?u=https%3A%2F%2Fx")),
       "_is_share_button: facebook sharer is a button")
    ck(not el._is_share_button(_us("https://fosstodon.org/@kicksecure")),
       "_is_share_button: a profile link is NOT a button")
    ck(not el._is_share_button(_us("https://example.test/share?url=x")),
       "_is_share_button: a non-share-host /share?url= is NOT excluded (host must be a platform)")
    ck(not el._is_share_button(_us("https://www.reddit.com/r/x/comments/1?title=foo&utm=a")),
       "_is_share_button: a real citation on a share host with a generic ?title= is KEPT "
       "(only an embedded page URL marks a button)")
    ck(el._is_share_button(_us("https://www.reddit.com/submit?url=https%3A%2F%2Fp")),
       "_is_share_button: reddit /submit?url=https%3A IS a button (percent-encoded page URL)")
    ck(el._is_share_button(_us("https://twitter.com/share?url=https://p/page")),
       "_is_share_button: embedded URL with a LITERAL colon is also a button (ai-review codex)")
    ck({"www.reddit.com", "twitter.com", "news.ycombinator.com", "t.me", "fosstodon.org",
        "facebook.com", "www.linkedin.com", "wa.me"} <= el._SHARE_HOSTS,
       "_SHARE_HOSTS covers the measured top-8 share hosts")

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

    # a TRANSIENT failure (DNS/timeout/refused) retries with a backoff pause BETWEEN attempts,
    # so a throttled-but-live host (archive.org refuses a burst, then serves) is not misjudged
    # dead. The backoff fires only between transient retries -- never after a terminal
    # alive/dead verdict, never after the last attempt. Drive check_url with a scripted
    # _probe_once + a recording _sleep (no real wait). No network.
    _orig_probe, _orig_sleep = el._probe_once, el._sleep

    def _scripted(verdicts):
        box = {"i": 0}

        def probe(_url, _timeout):
            v = verdicts[min(box["i"], len(verdicts) - 1)]
            box["i"] += 1
            return (v, v)
        return probe

    try:
        _sleeps: list[float] = []
        el._sleep = _sleeps.append

        el._probe_once = _scripted(["transient", "transient", "alive"])
        _reach, _ = el.check_url("https://throttled.test/", timeout=1, retries=2, backoff=0.01)
        ck(_reach is True and len(_sleeps) == 2,
           "transient-then-alive reads reachable; backoff fires between the 2 retries only: %r"
           % _sleeps)

        _sleeps.clear()
        el._probe_once = _scripted(["dead"])
        _reach, _ = el.check_url("https://gone.test/", timeout=1, retries=2, backoff=0.01)
        ck(_reach is False and _sleeps == [],
           "a terminal DEAD returns at once, no backoff slept: %r" % _sleeps)

        _sleeps.clear()
        el._probe_once = _scripted(["transient"])
        _reach, _ = el.check_url("https://down.test/", timeout=1, retries=2, backoff=0.01)
        ck(_reach is False and len(_sleeps) == 2,
           "all-transient fails after retries; no backoff after the LAST attempt: %r" % _sleeps)
    finally:
        el._probe_once, el._sleep = _orig_probe, _orig_sleep

    # per-host throttle: same-host request STARTS are spaced >= _HOST_MIN_INTERVAL (de-burst a
    # rate-limiting host like archive.org Wayback); the first hit and a DIFFERENT host never
    # wait, so parallelism across hosts is preserved. Drive _host_gate with a recording _sleep
    # (no real wait) and a small interval. No network.
    _orig_sleep2, _orig_interval = el._sleep, el._HOST_MIN_INTERVAL
    try:
        _hsleeps: list[float] = []
        el._sleep = _hsleeps.append
        el._HOST_MIN_INTERVAL = 0.5
        el._host_next_start.clear()
        el._host_gate("a.test")        # first hit: slot free -> no wait
        el._host_gate("a.test")        # same host again -> reserve + wait ~interval
        el._host_gate("b.test")        # different host -> free
        ck(len(_hsleeps) == 1 and abs(_hsleeps[0] - 0.5) < 0.2,
           "per-host throttle delays only the 2nd same-host start, other hosts free: %r"
           % _hsleeps)

        _hsleeps.clear()
        el._HOST_MIN_INTERVAL = 0
        el._host_next_start.clear()
        el._host_gate("a.test")
        el._host_gate("a.test")
        ck(_hsleeps == [], "interval 0 disables the throttle: %r" % _hsleeps)
    finally:
        el._sleep, el._HOST_MIN_INTERVAL = _orig_sleep2, _orig_interval
        el._host_next_start.clear()

    # the per-host gate must fire for EACH request START, including the HEAD->GET fallback
    # (a 403/405/501/429 on HEAD retries as GET in the SAME _probe_once): else that GET start
    # skips same-host spacing and bursts the very host the gate de-bursts. Drive _probe_once
    # with a stub opener (HEAD -> 403, GET -> 200) + a recording _host_gate. No network.
    _orig_gate, _orig_opener = el._host_gate, el._OPENER
    try:
        _gated: list[str] = []
        el._host_gate = _gated.append

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        class _FallbackOpener:
            def open(self, req, timeout=None):
                if req.get_method() == "HEAD":
                    raise urllib.error.HTTPError(req.full_url, 403, "no HEAD",
                                                 Message(), io.BytesIO(b""))
                return _Resp()

        el._OPENER = _FallbackOpener()
        _verdict, _ = el._probe_once("https://h.test/x", timeout=1)
        ck(_verdict == "alive" and _gated == ["h.test", "h.test"],
           "HEAD->GET fallback gates the host once PER request start (twice): %r" % _gated)

        _gated.clear()

        class _OkOpener:
            def open(self, req, timeout=None):
                return _Resp()

        el._OPENER = _OkOpener()
        _verdict, _ = el._probe_once("https://h.test/y", timeout=1)
        ck(_verdict == "alive" and _gated == ["h.test"],
           "a HEAD that succeeds gates the host exactly once (no double-count): %r" % _gated)
    finally:
        el._host_gate, el._OPENER = _orig_gate, _orig_opener

    # interleave spreads same-host URLs round-robin so a worker pool is not filled with workers
    # all sleeping on ONE throttled host while other hosts' URLs sit queued with free slots.
    _il = el._interleave_by_host({
        "https://a.test/1", "https://a.test/2", "https://a.test/3",
        "https://b.test/1", "https://c.test/1"})
    _hosts = [el.urlsplit(u).hostname for u in _il]
    ck(len(_il) == 5 and set(_hosts[:3]) == {"a.test", "b.test", "c.test"},
       "interleave_by_host round-robins hosts (first pass covers every host before a repeat): %r"
       % _hosts)

    sys.stdout.write("check_extlinks_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
