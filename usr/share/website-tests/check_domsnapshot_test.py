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
  - _scrub collapses the mount base in BOTH plain and encodeURIComponent form (the random port)
  - _normalize_manifest drops volatile response headers (date/etag/...) + scrubs the host in keys
  - _modes: default is one deterministic mode; an unknown mode is rejected
  - normalize_dir: scrubs text artifacts, drops volatile headers, copies the screenshot byte-for-byte
"""
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

    print("check_domsnapshot_test: %d pass, %d fail, 0 skip" % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
