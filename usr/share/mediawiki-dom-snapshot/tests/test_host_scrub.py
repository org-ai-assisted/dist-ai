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

# crafted manifest.json crash inputs: a RECEIVED cross-wiki manifest is untrusted, so a
# malformed entry (or top-level shape) must be skipped/refused, NOT crash the whole
# normalize. Each helper builds a minimal page dir with one real flat asset (ok.css) so a
# single malformed sibling is tolerated without tripping the all-malformed fail-loud guard.
def _mkmanifest(manifest_obj):
    s = Path(tempfile.mkdtemp()); d = Path(tempfile.mkdtemp())
    (s / "dom.html").write_text("<html></html>", encoding="utf-8")
    (s / "assets").mkdir()
    (s / "assets" / "ok.css").write_text(".x{}", encoding="utf-8")
    (s / "manifest.json").write_text(json.dumps(manifest_obj), encoding="utf-8")
    return s, d

_page = {"https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"}}
_good = {"https://%s/ok.css" % H: {"status": 200, "content_type": "text/css", "asset": "ok.css"}}

# asset: null -- `src_assets / None` would TypeError before the flat-name guard.
s, d = _mkmanifest({**_page, **_good,
    "https://%s/x.css" % H: {"status": 200, "content_type": "text/css", "asset": None}})
N.normalize_page_dir(s, d)  # must NOT raise
mout = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
assert any(v.get("asset") is None for v in mout.values()), ("asset-null-skip", mout)

# asset: a number -- same TypeError class, non-string asset value.
s, d = _mkmanifest({**_page, **_good,
    "https://%s/x.css" % H: {"status": 200, "content_type": "text/css", "asset": 12345}})
N.normalize_page_dir(s, d)  # must NOT raise
mout = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
assert any(v.get("asset") == 12345 for v in mout.values()), ("asset-number-skip", mout)

# non-dict entry -- `entry.get(...)`/`"asset" not in entry` would raise on a scalar entry.
s, d = _mkmanifest({**_page, **_good,
    "https://%s/weird" % H: "i-am-not-an-object"})
N.normalize_page_dir(s, d)  # must NOT raise
mout = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
assert "i-am-not-an-object" not in mout.values(), ("nondict-entry-skip", mout)

# non-string content_type -- `.startswith(...)` would crash on a number/list content_type.
s, d = _mkmanifest({**_page,
    "https://%s/c.css" % H: {"status": 200, "content_type": 999, "asset": "ok.css"}})
N.normalize_page_dir(s, d)  # must NOT raise (entry falls through to plain copy)
assert (d / "assets" / "ok.css").exists(), "non-string content_type entry was not copied"

# non-dict headers -- _normalize_headers would crash on `(headers or {}).items()`.
s, d = _mkmanifest({**_page, **_good,
    "https://%s/h.css" % H: {"status": 200, "content_type": "text/css", "asset": "ok.css",
                             "headers": "not-a-dict"}})
N.normalize_page_dir(s, d)  # must NOT raise
mout = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
assert any(v.get("headers") == "not-a-dict" for v in mout.values()), ("nondict-headers-skip", mout)

# non-string header value -- a crafted cache-control number (cache-control matches a
# HEADER_TOKEN_PATTERN and is not volatile-scrubbed) would crash pattern.sub(TypeError).
hv = N._normalize_headers({"cache-control": 12345})
assert hv.get("cache-control") == 12345, ("nonstr-header-value", hv)

# sibling snapshot files (console.json / storage.json / errors.json) are ALSO untrusted:
# json.loads' try/except catches parse errors, NOT valid-JSON-wrong-shape. Each normaliser
# must survive a crafted non-list / non-object / non-string-field without raising.
assert N._normalize_console({"a": 1}) == [], "console non-list must yield []"
assert N._normalize_console(5) == [], "console scalar must yield []"
assert N._normalize_console([{"type": "log", "text": 123}]) == [], "console non-str text skipped"
assert N._normalize_console([1, {"type": "log", "text": "x"}]) == [
    {"type": "log", "text": "x"}], "console non-dict item skipped"
sres = N._normalize_storage([1, 2])
assert sres["cookies"] == [] and sres["localStorage"] == {}, ("storage-nonobject", sres)
sres = N._normalize_storage({"cookies": [{"name": 123, "value": "x"}, "notdict"]})
assert isinstance(sres["cookies"], list), ("storage-badcookie", sres)
assert N._normalize_storage({"localStorage": [1, 2]})["localStorage"] == {}, "storage ls non-object"
eres = N._normalize_errors(5)
assert eres["http_errors"] == [] and eres["console_errors"] == [], ("errors-scalar", eres)
assert N._normalize_errors({"http_errors": {"a": 1}})["http_errors"] == [], "errors http non-list"
eres = N._normalize_errors({"http_errors": [{"status": 404, "url": 123}, "notdict"]})
assert eres["http_errors"] == [], ("errors-badurl-skip", eres)

# top-level non-object manifest -- a JSON list/scalar has no .items().
s = Path(tempfile.mkdtemp()); d = Path(tempfile.mkdtemp())
(s / "dom.html").write_text("<html></html>", encoding="utf-8")
(s / "assets").mkdir()
(s / "manifest.json").write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
N.normalize_page_dir(s, d)  # must NOT raise
assert json.loads((d / "manifest.json").read_text(encoding="utf-8")) == {}, "top-level list not emptied"
assert N.normalize_manifest(42) == {}, "scalar manifest not refused"
assert N.normalize_manifest(["a", "b"]) == {}, "list manifest not refused"

# all-malformed manifest -- EVERY asset entry is malformed. normalize must FAIL LOUD
# (non-zero / raise), not finish 0 with a near-empty mirror that reads as a clean diff.
s = Path(tempfile.mkdtemp()); d = Path(tempfile.mkdtemp())
(s / "dom.html").write_text("<html></html>", encoding="utf-8")
(s / "assets").mkdir()
(s / "assets" / "real.css").write_text(".x{}", encoding="utf-8")
(s / "manifest.json").write_text(json.dumps({**_page,
    "https://%s/a.css" % H: {"status": 200, "content_type": "text/css", "asset": None},
    "https://%s/b.css" % H: {"status": 200, "content_type": "text/css", "asset": None}}),
    encoding="utf-8")
raised = False
try:
    N.normalize_page_dir(s, d)
except SystemExit:
    raised = True
assert raised, "all-malformed manifest must fail loud, not emit a near-empty mirror as success"

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
