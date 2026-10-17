#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Canary for dist_ai.webcheck.domsnap's browser-free logic: the page-slug + page-list parse, the
mount-host scrub (plain AND percent-encoded), the manifest normalizer (volatile-header drop +
host scrub + re-sort), the mode catalog, and normalize_dir end-to-end on a fake raw tree. Playwright
is imported only inside capture(), so this runs everywhere (no browser) and a failure is a real
logic regression. The diff engine itself (diff.py) is reused verbatim and proven by the live lane.

Canary cases (each FAILS on a broken predicate):
  - page_slug('/')='index', nested path flattened; load_pages skips '#'/blank
  - _scrub collapses the mount base in BOTH plain and encodeURIComponent form (the random port),
    ANCHORED (a longer port sharing our prefix is not corrupted) + case-insensitive on the encoded
  - _normalize_manifest drops volatile response headers (date/etag/...) + scrubs the host in keys,
    surviving header VALUES, and the error string
  - _modes: default is one deterministic mode; an unknown mode is rejected
  - normalize_dir: scrubs text artifacts, drops volatile headers, copies the screenshot byte-for-byte
  - hardening: page_slug neutralizes '.'/'..'; _unique_slugs rejects a slug collision;
    _safe_component rejects a traversal label; _ignore_tls is secure-by-default on an https base
  - wiki lane: _wiki_env defaults + overrides; wiki-capture/-diff/-diff-baseline/-normalise build
    the correct relocated-engine (snapshot.py/diff.py/normalize.py) argv; wiki-promote rejects a
    traversal tag
"""
import argparse
import json
import os
import sys
import urllib.parse


def _load():
    here = os.path.dirname(os.path.realpath(__file__))
    pkg = os.path.normpath(os.path.join(here, "..", "..", "lib", "python3", "dist-packages"))
    if os.path.isdir(pkg) and pkg not in sys.path:
        sys.path.insert(0, pkg)
    from dist_ai.webcheck import domsnap
    return domsnap


def run():
    domsnap = _load()
    import tempfile
    from pathlib import Path

    stats = {"pass": 0, "fail": 0}

    def ck(cond, label):
        if cond:
            stats["pass"] += 1
        else:
            stats["fail"] += 1
            print("check_domsnapshot_test: FAIL: %s" % label)

    # --- page_slug / load_pages ----------------------------------------------------------------
    ck(domsnap.page_slug("/") == "index", "page_slug('/') is 'index'")
    ck(domsnap.page_slug("/analyze/") == "analyze", "page_slug strips surrounding slashes")
    ck(domsnap.page_slug("/git-diffs-lie/all/") == "git-diffs-lie_all", "page_slug flattens path")
    with tempfile.TemporaryDirectory() as tmp:
        conf = Path(tmp) / "p.conf"
        conf.write_text("# comment\n\n/\n/analyze/\n", encoding="utf-8")
        ck(domsnap.load_pages(conf) == ["/", "/analyze/"], "load_pages skips '#'/blank")

    # --- _scrub: plain + percent-encoded base --------------------------------------------------
    base = "http://127.0.0.1:38271"
    enc = urllib.parse.quote(base, safe="")
    dom = ('<a href="%s/x">x</a>'
           '<a href="https://t.co/share?url=%s%%2Ffoo">s</a>') % (base, enc)
    scrubbed = domsnap._scrub(dom, base)
    ck(base not in scrubbed, "_scrub removes the plain mount base")
    ck(enc not in scrubbed, "_scrub removes the percent-encoded mount base (random port)")
    ck(domsnap.HOST_PLACEHOLDER in scrubbed, "_scrub inserts the placeholder")

    # --- _normalize_manifest -------------------------------------------------------------------
    manifest = json.dumps({
        base + "/style.css": {"sha256": "abc", "size": 10, "headers":
                              {"content-type": "text/css", "date": "now", "etag": "x"}},
        base + "/a.js": {"sha256": "def", "size": 5, "headers": {"content-type": "text/javascript"}},
    })
    norm = json.loads(domsnap._normalize_manifest(manifest, base))
    keys = list(norm)
    ck(all(base not in k for k in keys), "_normalize_manifest scrubs the host in URL keys")
    css = norm[domsnap.HOST_PLACEHOLDER + "/style.css"]
    ck("date" not in css["headers"] and "etag" not in css["headers"],
       "_normalize_manifest drops volatile headers (date/etag)")
    ck("content-type" in css["headers"], "_normalize_manifest keeps stable headers")
    ck(keys == sorted(keys), "_normalize_manifest re-sorts keys")

    # --- _modes --------------------------------------------------------------------------------
    os.environ.pop("WEBCHECK_DOMSNAP_MODES", None)
    modes = domsnap._modes()
    ck(len(modes) == 1 and modes[0][2] == "desktop-light", "_modes default is one desktop-light mode")
    os.environ["WEBCHECK_DOMSNAP_MODES"] = "bogus-mode"
    try:
        domsnap._modes()
        ck(False, "_modes rejects an unknown mode")
    except SystemExit:
        ck(True, "_modes rejects an unknown mode")
    finally:
        os.environ.pop("WEBCHECK_DOMSNAP_MODES", None)

    # --- normalize_dir end-to-end --------------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "raw"
        md = raw / "index" / "desktop-light"
        md.mkdir(parents=True)
        (md / "dom.html").write_text('<a href="%s/x">x</a>' % base, encoding="utf-8")
        (md / "manifest.json").write_text(manifest, encoding="utf-8")
        (md / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\nFAKE")
        (md / "assets").mkdir()
        (md / "assets" / "abc.css").write_text("body{}", encoding="utf-8")
        fix = Path(tmp) / "fix"
        domsnap.normalize_dir(raw, fix, base)
        fmd = fix / "index" / "desktop-light"
        ck(base not in (fmd / "dom.html").read_text(encoding="utf-8"), "normalize_dir scrubs dom.html")
        fman = json.loads((fmd / "manifest.json").read_text(encoding="utf-8"))
        ck(all("date" not in e.get("headers", {}) for e in fman.values()),
           "normalize_dir drops volatile headers from the manifest")
        ck((fmd / "screenshot.png").read_bytes() == b"\x89PNG\r\n\x1a\nFAKE",
           "normalize_dir copies the screenshot byte-for-byte")
        ck((fmd / "assets" / "abc.css").exists(), "normalize_dir copies the assets dir")

    # --- hardening: _scrub anchors on a host/port boundary (case-sensitive) --------------------
    longer = "http://127.0.0.1:382719/x"   # a DIFFERENT port that merely starts with ours
    ck(domsnap._scrub(longer, base) == longer,
       "_scrub does not corrupt a longer port that shares our prefix (:38271 in :382719)")
    hostbase = "https://good.example"       # a hostname that is a prefix of a different host
    ck(domsnap._scrub("x=https://good.example.evil/a", hostbase) == "x=https://good.example.evil/a",
       "_scrub does not mask a longer hostname sharing our prefix (good.example in good.example.evil)")
    ck(domsnap._scrub("x=" + hostbase + "/a", hostbase) == "x=" + domsnap.HOST_PLACEHOLDER + "/a",
       "_scrub still collapses the exact base at a boundary")
    ck(domsnap._scrub("x=https://good.example:8443/a", hostbase) == "x=https://good.example:8443/a",
       "_scrub does not corrupt a same-host different-port origin (':' boundary)")
    enc_lower = enc.lower()   # a page may carry lowercase %3a where encodeURIComponent emits %3A
    ck(enc_lower not in domsnap._scrub("ref=" + enc_lower, base),
       "_scrub collapses a lower-cased percent-encoded base (case-folds the %XX hex)")
    pathbase = "https://x.test/app"          # a base WITH a path -> a path-case change must survive
    enc_pb_upper = urllib.parse.quote(pathbase, safe="").replace("app", "APP")
    ck(domsnap._scrub("u=" + enc_pb_upper, pathbase) == "u=" + enc_pb_upper,
       "_scrub does not mask a real path-case change (%2Fapp vs %2FAPP) -- only the hex folds")

    # --- hardening: _normalize_manifest scrubs header VALUES + the error string ----------------
    man2 = json.dumps({
        base + "/r.css": {"sha256": "a",
                          "headers": {"content-type": "text/css", "location": base + "/r.css/"}},
        base + "/bad": {"error": "body unavailable: fetch " + base + "/bad"},
    })
    n2 = json.loads(domsnap._normalize_manifest(man2, base))
    loc = n2[domsnap.HOST_PLACEHOLDER + "/r.css"]["headers"].get("location", "")
    ck(base not in loc and domsnap.HOST_PLACEHOLDER in loc,
       "_normalize_manifest scrubs the host in a surviving header value")
    ck(base not in n2[domsnap.HOST_PLACEHOLDER + "/bad"]["error"],
       "_normalize_manifest scrubs the host in the error string")

    # --- hardening: page_slug neutralizes '.'/'..' (no traversal out of the site dir) ----------
    ck(domsnap.page_slug("..") not in ("..", "."), "page_slug neutralizes '..'")
    ck(domsnap.page_slug(".") not in ("..", "."), "page_slug neutralizes '.'")

    # --- hardening: _unique_slugs rejects a collision, passes a clean list ----------------------
    domsnap._unique_slugs(["/", "/analyze/", "/quiz/"])
    ck(True, "_unique_slugs passes a collision-free list")
    try:
        domsnap._unique_slugs(["/a/b", "/a_b"])
        ck(False, "_unique_slugs rejects a slug collision")
    except SystemExit:
        ck(True, "_unique_slugs rejects a slug collision")

    # --- hardening: _safe_component accepts a plain label, rejects traversal --------------------
    ck(domsnap._safe_component("secure-terminal.github.io", "x") == "secure-terminal.github.io",
       "_safe_component accepts a plain label")
    for bad in ("..", ".", "", "a/b", "../x"):
        try:
            domsnap._safe_component(bad, "x")
            ck(False, "_safe_component rejects %r" % bad)
        except SystemExit:
            ck(True, "_safe_component rejects %r" % bad)

    # --- hardening: _safe_dir resolves + rejects root / shallow / relative targets --------------
    from pathlib import Path as _Pth
    ck(domsnap._safe_dir(_Pth("/home/user/private-cache/domsnap-wiki/baseline"), "x") is not None,
       "_safe_dir accepts a deep absolute dir")
    for bad in ("", ".", "/", "//", "/..", "/tmp/..", "/etc", "relative/dir"):
        try:
            domsnap._safe_dir(_Pth(bad), "x")
            ck(False, "_safe_dir rejects %r" % bad)
        except SystemExit:
            ck(True, "_safe_dir rejects %r" % bad)

    # --- hardening: _ignore_tls validates TLS unless the explicit opt-in is set -----------------
    os.environ.pop("WEBCHECK_DOMSNAP_INSECURE_TLS", None)
    ck(domsnap._ignore_tls() is False, "_ignore_tls validates TLS by default (no context-wide bypass)")
    os.environ["WEBCHECK_DOMSNAP_INSECURE_TLS"] = "1"
    ck(domsnap._ignore_tls() is True, "_ignore_tls honors the explicit opt-in")
    os.environ.pop("WEBCHECK_DOMSNAP_INSECURE_TLS", None)

    # --- wiki lane: env contract + engine argv mapping (no browser, no live wiki) ---------------
    with tempfile.TemporaryDirectory() as tmp:
        rawd = os.path.join(tmp, "raw")
        fixd = os.path.join(tmp, "fix")
        basel = os.path.join(tmp, "baseline")
        for k in ("PAGES_FILE", "BASE_URL", "TIMEOUT_MS"):
            os.environ.pop(k, None)          # test the defaults apply
        os.environ["RAW_DIR"] = rawd
        os.environ["FIX_DIR"] = fixd
        os.environ["BASELINE_DIR"] = basel

        env = domsnap._wiki_env()
        ck(env["BASE_URL"] == "https://www.kicksecure.com", "_wiki_env defaults BASE_URL to the wiki")
        ck(env["PAGES_FILE"].endswith("/wiki-pages.conf"), "_wiki_env defaults PAGES_FILE to the engine conf")
        ck(env["FIX_DIR"] == fixd and env["BASELINE_DIR"] == basel, "_wiki_env honors FIX/BASELINE overrides")

        calls = []

        class _R:
            returncode = 0

        orig_run = domsnap.subprocess.run

        def rec(cmd, **kw):
            calls.append((list(cmd), kw.get("env")))
            return _R()

        domsnap.subprocess.run = rec
        try:
            domsnap._cmd_wiki_capture(argparse.Namespace(tag="before"))
            argv, cenv = calls[-1]
            assert cenv is not None
            ck(argv == [sys.executable, domsnap.SNAPSHOT_PY], "wiki-capture invokes the engine snapshot.py")
            ck(cenv.get("BASE_URL") == "https://www.kicksecure.com", "wiki-capture passes the wiki env")
            ck(cenv.get("RAW_DIR") == rawd + "/before", "wiki-capture scopes RAW_DIR under the run tag")

            domsnap._cmd_wiki_diff(argparse.Namespace(a="t1", b="t2", brief=True))
            argv, _ = calls[-1]
            ck(argv == [sys.executable, domsnap.DIFF_PY, fixd + "/t1", fixd + "/t2", "--brief"],
               "wiki-diff builds the diff.py argv (two fixture tags + --brief)")

            domsnap._cmd_wiki_diff_baseline(argparse.Namespace(tag="cand", brief=False))
            argv, _ = calls[-1]
            ck(argv == [sys.executable, domsnap.DIFF_PY, basel, fixd + "/cand"],
               "wiki-diff-baseline builds the diff.py argv (baseline vs tag)")

            os.makedirs(os.path.join(rawd, "before", "Homepage"))
            calls.clear()
            domsnap._cmd_wiki_normalise(argparse.Namespace(tag="before"))
            ck(any(a[:2] == [sys.executable, domsnap.NORMALIZE_PY]
                   and a[2].endswith("/before/Homepage") and a[3].endswith("/before/Homepage")
                   for a, _ in calls),
               "wiki-normalise invokes normalize.py per raw page dir, scoped under the tag")

            try:
                domsnap._cmd_wiki_promote(argparse.Namespace(tag="../escape"))
                ck(False, "wiki-promote rejects a traversal tag")
            except SystemExit:
                ck(True, "wiki-promote rejects a traversal tag")
            try:
                domsnap._cmd_wiki_capture(argparse.Namespace(tag="../escape"))
                ck(False, "wiki-capture rejects a traversal tag")
            except SystemExit:
                ck(True, "wiki-capture rejects a traversal tag")

            # E: an absent/empty raw tag must NOT destroy a prior good fixture (check raw first).
            os.makedirs(os.path.join(fixd, "survivor"))
            with open(os.path.join(fixd, "survivor", "dom.html"), "w", encoding="utf-8") as fh:
                fh.write("prior good fixture")
            rc_e = domsnap._cmd_wiki_normalise(argparse.Namespace(tag="survivor"))  # rawd/survivor absent
            ck(rc_e == 1 and os.path.exists(os.path.join(fixd, "survivor", "dom.html")),
               "wiki-normalise with absent raw returns 1 and preserves the prior fixture")

            # F: RAW_DIR == FIX_DIR must be rejected (clearing fix would delete the raw input).
            os.makedirs(os.path.join(rawd, "aliastag", "Page"))
            os.environ["FIX_DIR"] = rawd   # alias source and destination
            try:
                domsnap._cmd_wiki_normalise(argparse.Namespace(tag="aliastag"))
                ck(False, "wiki-normalise rejects RAW_DIR == FIX_DIR")
            except SystemExit:
                ck(True, "wiki-normalise rejects RAW_DIR == FIX_DIR")
            finally:
                os.environ["FIX_DIR"] = fixd
        finally:
            domsnap.subprocess.run = orig_run
            for k in ("RAW_DIR", "FIX_DIR", "BASELINE_DIR"):
                os.environ.pop(k, None)

    print("check_domsnapshot_test: %d pass, %d fail, 0 skip" % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
