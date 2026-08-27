#!/usr/bin/python3 -Bsu
"""Unit test for the cross-wiki host scrub (DOM_DIFF_HOST_SCRUB).

A before/after diff served on DIFFERENT hostnames (old.whonix.org vs
www.whonix.org) must not flag every absolute URL, nor leak the true host.
_scrub_hosts collapses the configured hostnames to a placeholder across every
surface a diff compares: the HTML, the text asset bodies (CSS/JS/SVG/JSON), the
manifest URL keys, response header values (Onion-Location/Link/Location...),
cookie/storage values, console + errors message text, and the verbatim JSON
copies (computed_styles/hover_styles/iframes_shadow). Matching is case-insensitive
so a differing host casing still collapses. When DOM_DIFF_HOST_SCRUB is unset it
must be a complete no-op (same-host diffs).

Run directly: python3 tests/test_host_scrub.py
"""
import os
import subprocess
import sys
from pathlib import Path

LIB = str(Path(__file__).resolve().parent.parent)
HOST = 'old.test.invalid'


def _import_with_env(value):
    """Import a FRESH normalize module with DOM_DIFF_HOST_SCRUB set to value.

    HOST_SCRUB is computed at import time, so each case runs in its own process.
    """
    env = dict(os.environ)
    if value is None:
        env.pop('DOM_DIFF_HOST_SCRUB', None)
    else:
        env['DOM_DIFF_HOST_SCRUB'] = value
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
assert N._is_text_asset("application/json")
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

# response header values (Onion-Location/Link/Location/Content-Location/SourceMap)
hdrs = N._normalize_headers({
    "Onion-Location": "https://%s/wiki/Page" % H,
    "Location": "https://%s/wiki/Other" % H,
    "Content-Location": "https://%s/wiki/Canon" % H,
    "Link": "<https://%s/w/load.php>; rel=preload" % H,
    "SourceMap": "https://%s/w/load.php.map" % H,
})
assert (not any(H in v for v in hdrs.values())) == active, ("headers", active, hdrs)

# cookie value+domain and localStorage/sessionStorage values (keys chosen to
# NOT match session/drop patterns, so value is kept -- isolating the host-scrub)
st = N._normalize_storage({
    "cookies": [{"name": "prefs", "value": "https://%s/x" % H, "domain": H, "path": "/"}],
    "localStorage": {"lastPage": "https://%s/wiki/Page" % H},
    "sessionStorage": {"ref": "https://%s/w/index.php" % H},
})
leak = (
    any(H in str(c.get("value")) or H in str(c.get("domain")) for c in st["cookies"])
    or any(H in str(v) for v in st["localStorage"].values())
    or any(H in str(v) for v in st["sessionStorage"].values())
)
assert (not leak) == active, ("storage", active, st)

# console.json
cons = N._normalize_console([{"type": "log", "text": "loaded https://%s/w/load.php" % H}])
assert (H not in cons[0]["text"]) == active, ("console", active, cons)

# errors.json console_errors (delegates to _normalize_console)
errs = N._normalize_errors({"console_errors": [{"type": "error", "text": "boom https://%s/x" % H}]})
assert (H not in errs["console_errors"][0]["text"]) == active, ("errors-console", active, errs)

# errors.json request_failures[].failure: raw browser error text embedding the URL
rf = N._normalize_errors({"request_failures": [
    {"url": "https://%s/wiki/Page" % H, "failure": "net::ERR_FAILED at https://%s/wiki/Page" % H}]})
assert (H not in rf["request_failures"][0]["failure"]) == active, ("request-failure", active, rf)

# mixed-case host: a differing casing must still collapse (active only), while
# scheme/path bytes are preserved intact
if active:
    mixed = N._scrub_hosts("HTTPS://Old.Test.Invalid/x?y=1")
    assert H not in mixed.lower(), mixed
    assert placeholder in mixed, mixed
    assert mixed.endswith("/x?y=1"), mixed
    assert mixed.upper().startswith("HTTPS://"), mixed

# asset body (CSS) + verbatim JSON copies + JSON asset body via normalize_page_dir
src = Path(tempfile.mkdtemp()); dst = Path(tempfile.mkdtemp())
(src / "dom.html").write_text("<html></html>", encoding="utf-8")
(src / "assets").mkdir()
(src / "assets" / "a.css").write_text(".x{background:url(https://%s/img.png)}" % H, encoding="utf-8")
(src / "assets" / "d.json").write_text('{"u":"https://%s/api"}' % H, encoding="utf-8")
for fn in ("computed_styles.json", "hover_styles.json", "iframes_shadow.json"):
    (src / fn).write_text('{"u":"https://%s/w/load.php"}' % H, encoding="utf-8")
(src / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/skins/Donation_Panel.css?v=1" % H: {"status": 200, "content_type": "text/css", "asset": "a.css", "sha256": "x", "size": 1},
    "https://%s/w/data.json?v=1" % H: {"status": 200, "content_type": "application/json", "asset": "d.json", "sha256": "y", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(src, dst)
css = list((dst / "assets").glob("*.css"))
assert css, "no css asset written"
body = css[0].read_text(encoding="utf-8")
assert (H not in body) == active, ("asset-body", active, body)
if active:
    assert placeholder in body, body

# verbatim JSON copies must be host-scrubbed too
for fn in ("computed_styles.json", "hover_styles.json", "iframes_shadow.json"):
    text = (dst / fn).read_text(encoding="utf-8")
    assert (H not in text) == active, ("page-json", fn, active, text)

# JSON asset body must be host-scrubbed (routed via _is_text_asset)
jbody = "".join(p.read_text(encoding="utf-8") for p in (dst / "assets").glob("*.json"))
assert jbody, "no json asset written"
assert (H not in jbody) == active, ("json-asset", active, jbody)

# path-traversal: entry["asset"] is untrusted (a received cross-wiki manifest); a
# ../-escaping (or absolute) asset path must be REFUSED, not read+copied into the output
# tree -- otherwise an arbitrary readable file leaks (arb-file-read). Independent of scrub.
secret_marker = "TOP-SECRET-DECOY-DO-NOT-COPY"
src2 = Path(tempfile.mkdtemp()); dst2 = Path(tempfile.mkdtemp())
(src2 / "dom.html").write_text("<html></html>", encoding="utf-8")
(src2 / "assets").mkdir()
(src2 / "secret.txt").write_text(secret_marker, encoding="utf-8")  # decoy OUTSIDE assets/
(src2 / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/evil" % H: {"status": 200, "content_type": "text/css",
                            "asset": "../secret.txt", "sha256": "x", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(src2, dst2)
leaked = any(secret_marker in p.read_text(encoding="utf-8", errors="replace")
             for p in dst2.rglob("*") if p.is_file())
assert not leaked, ("path-traversal-asset-leak", sorted(str(p) for p in dst2.rglob("*")))

# nested asset name: a path separator is off-spec (names are flat <sha256>.<ext>) and the
# plain-copy branch would crash (dst/assets/sub is never mkdir'd -> FileNotFoundError). It
# must be REFUSED, not crash the whole normalize. Reproduces in no-op mode (the copy branch).
src3 = Path(tempfile.mkdtemp()); dst3 = Path(tempfile.mkdtemp())
(src3 / "dom.html").write_text("<html></html>", encoding="utf-8")
(src3 / "assets" / "sub").mkdir(parents=True)
(src3 / "assets" / "sub" / "file.css").write_text(".x{}", encoding="utf-8")
(src3 / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/nested" % H: {"status": 200, "content_type": "text/css",
                              "asset": "sub/file.css", "sha256": "x", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(src3, dst3)  # must NOT raise
assert not (dst3 / "assets" / "sub").exists(), "nested asset was copied instead of refused"

print("OK active=%s" % active)
"""


def run(value):
    env = _import_with_env(value)
    r = subprocess.run(
        [sys.executable, '-c', CHECK, LIB],
        env=env, capture_output=True, text=True,
    )
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit('FAILED for DOM_DIFF_HOST_SCRUB=%r' % value)
    print('  %s -> %s' % ('scrub active' if value else 'default (no-op)', r.stdout.strip()))


if __name__ == '__main__':
    run(HOST)   # scrub active: hosts collapse across html, manifest, asset bodies
    run(None)   # default: complete no-op
    print('all host-scrub tests passed')
