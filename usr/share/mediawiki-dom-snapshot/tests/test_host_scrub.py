#!/usr/bin/env python3
"""Unit test for the cross-wiki host scrub (DOM_DIFF_HOST_SCRUB).

A before/after diff served on DIFFERENT hostnames (old.whonix.org vs
www.whonix.org) must not flag every absolute URL. _scrub_hosts collapses the
configured hostnames to a placeholder across the THREE surfaces a diff compares:
the HTML, the text asset bodies (CSS/JS/SVG), and the manifest URL keys. When
DOM_DIFF_HOST_SCRUB is unset it must be a complete no-op (same-host diffs).

Run directly: python3 tests/test_host_scrub.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

LIB = str(Path(__file__).resolve().parent.parent)
HOST = "old.test.invalid"


def _import_with_env(value):
    """Import a FRESH normalize module with DOM_DIFF_HOST_SCRUB set to value.

    HOST_SCRUB is computed at import time, so each case runs in its own process.
    """
    env = dict(os.environ)
    if value is None:
        env.pop("DOM_DIFF_HOST_SCRUB", None)
    else:
        env["DOM_DIFF_HOST_SCRUB"] = value
    return env


CHECK = r"""
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import normalize as N

active = bool(N.HOST_SCRUB)
H = "old.test.invalid"
placeholder = N.HOST_SCRUB_PLACEHOLDER

# _is_text_asset
assert N._is_text_asset("text/css")
assert N._is_text_asset("application/javascript")
assert N._is_text_asset("image/svg+xml")
assert not N._is_text_asset("image/png")
assert not N._is_text_asset("font/woff2")

# HTML
html = N.normalize_html("<a href='https://%s/p'>x</a>" % H)
assert (H not in html) == active, ("html", active, html)

# manifest URL keys
m = {"https://%s/skins/x.css?v=1" % H: {"status": 200, "content_type": "text/css", "asset": "a.css", "sha256": "x", "size": 1}}
nm = N.normalize_manifest(m)
assert (not any(H in k for k in nm)) == active, ("manifest", active, list(nm))

# asset body (CSS) via normalize_page_dir
src = Path(tempfile.mkdtemp()); dst = Path(tempfile.mkdtemp())
(src / "dom.html").write_text("<html></html>", encoding="utf-8")
(src / "assets").mkdir()
(src / "assets" / "a.css").write_text(".x{background:url(https://%s/img.png)}" % H, encoding="utf-8")
(src / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/skins/Donation_Panel.css?v=1" % H: {"status": 200, "content_type": "text/css", "asset": "a.css", "sha256": "x", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(src, dst)
css = list((dst / "assets").glob("*.css"))
assert css, "no css asset written"
body = css[0].read_text(encoding="utf-8")
assert (H not in body) == active, ("asset-body", active, body)
if active:
    assert placeholder in body, body

print("OK active=%s" % active)
"""


def run(value):
    env = _import_with_env(value)
    r = subprocess.run(
        [sys.executable, "-c", CHECK, LIB],
        env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit("FAILED for DOM_DIFF_HOST_SCRUB=%r" % value)
    print("  %s -> %s" % ("scrub active" if value else "default (no-op)", r.stdout.strip()))


if __name__ == "__main__":
    run(HOST)   # scrub active: hosts collapse across html, manifest, asset bodies
    run(None)   # default: complete no-op
    print("all host-scrub tests passed")
