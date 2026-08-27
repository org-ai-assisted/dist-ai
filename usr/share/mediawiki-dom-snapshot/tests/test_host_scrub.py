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

# prettify() DoS: a deeply-nested untrusted dom.html amplifies O(N x depth) under prettify.
# normalize_html must NOT amplify -- past the depth bound it emits the compact O(N) form.
_deep = "<div>" * 2000 + "x" + "</div>" * 2000
_out_deep = N.normalize_html(_deep)
assert len(_out_deep) < 20 * len(_deep), ("prettify-dos-amplification", len(_deep), len(_out_deep))
assert "\n" in N.normalize_html("<div><p>hi</p></div>"), "a normal shallow page still prettifies"

# _scrub_script_text: the mw.user.options.set matcher must skip a literal "});" INSIDE a
# string value and drop the WHOLE statement, not truncate at the embedded });.
_js = 'a=1; mw.user.options.set({"x":"a});b","y":2}); real();'
_sc = N._scrub_script_text(_js)
assert "mw.user.options.set" not in _sc, ("options-set-not-dropped", _sc)
assert "real();" in _sc and '"y":2' not in _sc, ("options-set-truncated-early", _sc)

# manifest URL keys
m = {"https://%s/skins/x.css?v=1" % H: {"status": 200, "content_type": "text/css", "asset": "a.css", "sha256": "x", "size": 1}}
nm = N.normalize_manifest(m)
assert (not any(H in k for k in nm)) == active, ("manifest", active, list(nm))

# _normalize_url: an OPAQUE scheme (data:/javascript:/mailto:) with a literal '?' is NOT
# a query -> pass through unchanged, not parse_qsl-corrupted; but http(s) and relative
# URLs still get their volatile query normalized.
assert N._normalize_url("data:text/html,x?y=1</script>") == "data:text/html,x?y=1</script>"
assert N._normalize_url("javascript:f()?g") == "javascript:f()?g"
assert "version=SCRUBBED" in N._normalize_url("https://%s/w/load.php?version=abc&x=1" % H)
assert "version=SCRUBBED" in N._normalize_url("/w/load.php?version=abc&x=1")

# normalize_manifest: drop the page's OWN url (+ ?/# variants), NOT an unrelated entry
# that merely shares its prefix (startswith over-match erased a legit manifest entry).
_pm = "https://%s/wiki/A" % H
_nmp = N.normalize_manifest({
    _pm: {"status": 200, "content_type": "text/html"},
    "https://%s/wiki/API_documentation.css" % H: {"status": 200, "content_type": "text/css"},
}, page_url=_pm)
assert any("API_documentation.css" in k for k in _nmp), ("prefix-sibling-erased", list(_nmp))
assert not any(k.endswith("/wiki/A") for k in _nmp), ("page-url-not-dropped", list(_nmp))

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

# host-scrub FAILS CLOSED on a non-string field: an untrusted received snapshot could
# carry a non-string (list/dict) header/cookie/storage value embedding the host, which the
# isinstance guards must REDACT, not pass through raw. Independent of scrub mode -- a
# malformed non-string value is redacted either way, so the host never leaks.
hdr_ns = N._normalize_headers({"Onion-Location": ["https://%s/x" % H]})
assert H not in json.dumps(hdr_ns), ("header-nonstring-leak", hdr_ns)
st_ns = N._normalize_storage({
    "cookies": [{"name": "p", "value": ["https://%s/x" % H], "domain": {"h": H}, "path": "/"}],
    "localStorage": {"k": ["https://%s/x" % H]},
})
assert H not in json.dumps(st_ns), ("storage-nonstring-leak", st_ns)

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
(src2 / "assets" / "ok.css").write_text(".ok{}", encoding="utf-8")  # a valid asset alongside
(src2 / "secret.txt").write_text(secret_marker, encoding="utf-8")  # decoy OUTSIDE assets/
(src2 / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/ok.css" % H: {"status": 200, "content_type": "text/css", "asset": "ok.css", "sha256": "o", "size": 1},
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
(src3 / "assets" / "ok.css").write_text(".ok{}", encoding="utf-8")  # a valid asset alongside
(src3 / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/ok.css" % H: {"status": 200, "content_type": "text/css", "asset": "ok.css", "sha256": "o", "size": 1},
    "https://%s/nested" % H: {"status": 200, "content_type": "text/css",
                              "asset": "sub/file.css", "sha256": "x", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(src3, dst3)  # must NOT raise
assert not (dst3 / "assets" / "sub").exists(), "nested asset was copied instead of refused"

# all-REFUSED manifest: if EVERY asset entry is refused (all ../-escaping names) the mirror
# is near-empty just like an all-malformed one, so normalize must FAIL LOUD, not exit 0 as a
# clean pass. The fail-loud tally counts refused + missing-source drops, not only shape errors.
srcr = Path(tempfile.mkdtemp()); dstr = Path(tempfile.mkdtemp())
(srcr / "dom.html").write_text("<html></html>", encoding="utf-8")
(srcr / "assets").mkdir()
(srcr / "manifest.json").write_text(json.dumps({
    "https://%s/a" % H: {"status": 200, "content_type": "text/css", "asset": "../x.css", "sha256": "1", "size": 1},
    "https://%s/b" % H: {"status": 200, "content_type": "text/css", "asset": "../../y.css", "sha256": "2", "size": 1},
}), encoding="utf-8")
_refused_raised = False
try:
    N.normalize_page_dir(srcr, dstr)
except SystemExit:
    _refused_raised = True
assert _refused_raised, "an all-refused manifest must fail loud, not mirror empty and exit 0"

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

# non-string header value -- a crafted number/list (cache-control matches a
# HEADER_TOKEN_PATTERN and is not volatile-scrubbed) must not crash and must FAIL CLOSED:
# _normalize_headers host-scrubs every value, so a non-string is redacted, not passed raw.
hv = N._normalize_headers({"cache-control": 12345})
assert hv.get("cache-control") == "SCRUBBED", ("nonstr-header-value", hv)

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

# content_type does NOT gate the host scrub: a MISLABELED text asset (css whose
# manifest content_type is wrong / omitted / mixed-case) must still be scrubbed at
# the byte level, else the host leaks via the verbatim-copy else branch. AND a genuine
# binary asset (no host bytes, incl invalid-UTF-8) must be byte-identical in/out -- the
# no-corruption half, so a future lossy-decode reintroduction is caught.
srcm = Path(tempfile.mkdtemp()); dstm = Path(tempfile.mkdtemp())
(srcm / "dom.html").write_text("<html></html>", encoding="utf-8")
(srcm / "assets").mkdir()
for fn in ("m1.css", "m2.css", "m3.css"):
    (srcm / "assets" / fn).write_text(".x{background:url(https://%s/i.png)}" % H, encoding="utf-8")
binblob = bytes(range(256)) * 4  # no host bytes; includes invalid-UTF-8
(srcm / "assets" / "b.bin").write_bytes(binblob)
(srcm / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/wrong" % H: {"status": 200, "content_type": "application/octet-stream", "asset": "m1.css", "sha256": "a", "size": 1},
    "https://%s/omitted" % H: {"status": 200, "asset": "m2.css", "sha256": "b", "size": 1},
    "https://%s/mixed" % H: {"status": 200, "content_type": "Text/CSS", "asset": "m3.css", "sha256": "c", "size": 1},
    "https://%s/blob" % H: {"status": 200, "content_type": "application/octet-stream", "asset": "b.bin", "sha256": "z", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(srcm, dstm)
# (a) mislabeled text: the host is absent from the output when scrubbing is active
mout = b"".join(p.read_bytes() for p in (dstm / "assets").glob("*") if p.is_file())
assert (H.encode() not in mout) == active, ("mislabeled-content-type-leak", active, mout[:120])
# (b) binary no-corruption: the blob is byte-identical (no host bytes -> no rewrite), both modes
assert any(p.read_bytes() == binblob for p in (dstm / "assets").glob("*") if p.is_file()), \
    "binary asset was not copied byte-identical (a lossy UTF-8 round-trip would mangle it)"

# text-branch no-corruption: a body that is NOT valid UTF-8 but is labeled as text
# (css/js) or fetched from a modules=startup / load.php URL must NOT be
# errors="replace"-mangled into the canonical output. content_type is untrusted, so it
# is decoded STRICTLY; on failure the body is byte-copied (host-scrubbed at the byte
# level), NOT U+FFFD-mangled. Output is byte-identical to input, except the host bytes
# when scrubbing is active. Canary: revert the strict decode -> U+FFFD appears -> fail.
bad = b"\xff\xfe .x{color:red} /* not utf-8 */"
badhost = b"\xff\xfe url(https://" + H.encode() + b"/i.png) \x80\x81"
srct = Path(tempfile.mkdtemp()); dstt = Path(tempfile.mkdtemp())
(srct / "dom.html").write_text("<html></html>", encoding="utf-8")
(srct / "assets").mkdir()
(srct / "assets" / "css_nohost.css").write_bytes(bad)      # css branch, no host bytes
(srct / "assets" / "css_host.css").write_bytes(badhost)    # css branch, host bytes
(srct / "assets" / "js_load.js").write_bytes(bad)          # load.php branch, no host bytes
(srct / "assets" / "js_start.js").write_bytes(badhost)     # modules=startup branch, host bytes
# multi-module URLs (%7C) so the single-module load.php drop does not remove the js entries
(srct / "manifest.json").write_text(json.dumps({
    "https://%s/wiki/Page" % H: {"status": 200, "content_type": "text/html"},
    "https://%s/skins/x.css" % H: {"status": 200, "content_type": "text/css", "asset": "css_nohost.css", "sha256": "1", "size": 1},
    "https://%s/skins/y.css" % H: {"status": 200, "content_type": "text/css", "asset": "css_host.css", "sha256": "2", "size": 1},
    "https://%s/w/load.php?modules=foo%%7Cbar" % H: {"status": 200, "content_type": "application/javascript", "asset": "js_load.js", "sha256": "3", "size": 1},
    "https://%s/w/load.php?modules=startup%%7Cfoo" % H: {"status": 200, "content_type": "application/javascript", "asset": "js_start.js", "sha256": "4", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(srct, dstt)
outs = [p.read_bytes() for p in (dstt / "assets").glob("*") if p.is_file()]
# no U+FFFD replacement char anywhere: the invalid bytes were preserved, not mangled
assert all(b"\xef\xbf\xbd" not in o for o in outs), ("text-branch mangled to U+FFFD", active, outs)
# the no-host bodies (css + js) survive byte-identical in BOTH modes
assert sum(o == bad for o in outs) >= 2, ("no-host text bodies not byte-identical", active, outs)
# the host-bearing bodies (css + js) are byte-identical except a host byte-scrub when active
assert sum(o == N._scrub_hosts_bytes(badhost) for o in outs) >= 2, \
    ("host-bearing text bodies not byte-identical minus host", active, outs)

# C3: _is_single_module_loadphp -- "%7C" (URL-encoded "|") must be matched case-
# INsensitively. A lowercase "%7c" multi-module load.php URL must NOT misclassify as a
# single module and get the whole entry DROPPED (a silent regression-detection gap).
# Canary: revert to the case-sensitive compare -> the lowercase %7c entry is dropped.
assert N._is_single_module_loadphp("https://h/w/load.php?modules=jquery")            # true single
assert not N._is_single_module_loadphp("https://h/w/load.php?modules=jquery%7Cfoo")  # upper multi
assert not N._is_single_module_loadphp("https://h/w/load.php?modules=jquery%7cfoo")  # lower multi
mc = N.normalize_manifest({
    "https://h/w/load.php?modules=jquery%7cfoo": {"status": 200, "content_type": "application/javascript"},
})
assert any("load.php" in k for k in mc), ("C3 lowercase-%7c multi-module dropped", list(mc))

# Finding-2: _scrub_script_text -- the JSON string-value regex must consume an ESCAPED
# quote (\") so a token value like "ab\"cd1234" is scrubbed WHOLE. A plain "[^"]*" stops
# at the escaped quote and leaks the tail. Canary: revert to "[^"]*" -> "cd1234" leaks.
leaky = '{"csrfToken":"ab\\"cd1234"}'
scrubbed_js = N._scrub_script_text(leaky)
assert "cd1234" not in scrubbed_js, ("Finding-2 escaped-quote leak", scrubbed_js)
assert '"csrfToken":"SCRUBBED"' in scrubbed_js, ("Finding-2 token not scrubbed", scrubbed_js)

# Finding-1 (LEAK): overlapping HOST_SCRUB entries must be applied LONGEST-first, so a
# shorter host that is a substring of a longer one (apex "test.invalid" inside subdomain
# "old.test.invalid") cannot consume the inner match and leave the enclosing host's fragment
# ("old.") behind. Order-in-config must NOT matter after the length-descending sort -- this
# config lists the SHORTER host first, the exact naive-order leak. Canary: drop the sort ->
# "old.test.invalid" scrubs to "old.wiki-host.invalid" and the real-host fragment leaks.
if active and set(N.HOST_SCRUB) >= {"test.invalid", "old.test.invalid"}:
    for probe in ("old.test.invalid", "OLD.TEST.INVALID", "see https://old.test.invalid/p now"):
        s = N._scrub_hosts(probe)
        assert "old." not in s.lower() and "test.invalid" not in s.lower(), ("host-order-leak", probe, s)
        sb = N._scrub_hosts_bytes(probe.encode())
        assert b"old." not in sb.lower() and b"test.invalid" not in sb.lower(), ("host-order-leak-bytes", probe, sb)

# Finding-3 (FALSE-NEGATIVE DROP): modules=startup is MW's standalone startup request and is
# ALWAYS requested alone, so the single-module drop must EXEMPT it -- otherwise startup.js is
# stripped from the manifest AND the startup-body version scrub becomes dead code (a real
# startup.js regression can never surface). Canary: drop the exemption -> the entry is dropped.
assert not N._is_single_module_loadphp("https://h/w/load.php?modules=startup")
assert not N._is_single_module_loadphp("https://h/w/load.php?modules=startup&only=scripts&raw=1")
assert N._is_single_module_loadphp("https://h/w/load.php?modules=jquery")  # a real single module still drops
_sm = N.normalize_manifest({
    "https://h/w/load.php?modules=startup&only=scripts": {"status": 200, "content_type": "application/javascript"},
})
assert any("modules=startup" in k for k in _sm), ("startup entry dropped", list(_sm))

# ... and the startup-body version scrub is now REACHABLE (was dead code while startup entries
# were dropped): a version hash in mw.loader.register(...) must be scrubbed in the emitted body.
_ss = Path(tempfile.mkdtemp()); _sd = Path(tempfile.mkdtemp())
(_ss / "dom.html").write_text("<html></html>", encoding="utf-8")
(_ss / "assets").mkdir()
(_ss / "assets" / "startup.js").write_text('mw.loader.register([["mod.name","1eggf"]]);', encoding="utf-8")
(_ss / "manifest.json").write_text(json.dumps({
    "https://h/wiki/Page": {"status": 200, "content_type": "text/html"},
    "https://h/w/load.php?modules=startup&only=scripts": {"status": 200, "content_type": "application/javascript", "asset": "startup.js", "sha256": "s", "size": 1},
}), encoding="utf-8")
N.normalize_page_dir(_ss, _sd)
_sjs = "".join(p.read_text(encoding="utf-8") for p in (_sd / "assets").glob("*.js"))
assert _sjs, "startup.js not written -- entry was dropped?"
assert "1eggf" not in _sjs and "SCRUBBED" in _sjs, ("startup body not normalized", _sjs)

# The O(N) whitespace-sensitivity precompute must keep the SAME semantics as a per-node
# ancestor walk: a whitespace run inside a whitespace-sensitive element (even nested under
# a non-sensitive child) is PRESERVED; a run in ordinary flow COLLAPSES to one space.
_wsx = N.normalize_html("<pre>a   b<span>c   d</span></pre><p>e   f</p>")
assert "a   b" in _wsx and "c   d" in _wsx, ("sensitive whitespace lost", _wsx)
assert "e   f" not in _wsx and "e f" in _wsx, ("flow whitespace not collapsed", _wsx)

# DoS (amplification): a pathologically deep untrusted dom.html must be bounded by the
# size+depth cap at the TOP of normalize_html, ahead of every pass that costs more than
# O(N). Two shapes, both must stay under budget:
#  - a "comb" with a text node at every level -- a per-text-node ancestor walk would be
#    O(N*depth);
#  - NESTED whitespace-sensitive tags (<pre><pre>...) -- collecting sensitive string ids
#    with a find_all(string) PER sensitive tag re-walks each subtree, O(depth^2). The
#    precompute is one O(N) stacked descent instead, and the cap runs first so neither can
#    amplify.
# Canary: move the cap back below _canonicalise_whitespace, or restore the find_all-per-tag
# precompute -> the nested-<pre> case blows the budget (~47s at D=20000). Run once (no-op
# config) since the path is scrub-independent.
if not active:
    import time as _time
    for _shape in (
        "".join("<div>t%d " % i for i in range(40000)) + "x" + "</div>" * 40000,
        "<pre>" * 20000 + "x" + "</pre>" * 20000,
    ):
        _t0 = _time.monotonic()
        N.normalize_html(_shape)
        assert _time.monotonic() - _t0 < 15.0, (
            "deep-tree amplification bypassed the cap", len(_shape))

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
    ## Overlapping hosts, SHORTER listed FIRST: exercises the longest-match-first ordering
    ## (Finding-1). A naive in-config order would leak the "old." fragment out of the longer
    ## host; the length-descending sort makes config order irrelevant.
    run('test.invalid,old.test.invalid')
    run(None)   # default: complete no-op
    print('all host-scrub tests passed')
