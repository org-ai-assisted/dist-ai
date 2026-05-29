#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Rewrite a captured page directory into a stable, diff-friendly form.

Input layout (produced by snapshot.py):
    <src>/<page>/
        dom.html
        screenshot.png
        manifest.json
        assets/<sha256>.<ext>

Output layout (one-to-one mirror; only dom.html and manifest.json
change content; screenshot.png and assets/* are bit-identical copies):
    <dst>/<page>/
        dom.html          per-request volatility scrubbed
        screenshot.png    copy
        manifest.json     URLs scrubbed of volatile query params
        assets/...        copies (sha256-identified, already canonical)

Usage:
    normalize.py <input-page-dir>  <output-page-dir>
    normalize.py <input-html-file> <output-html-file>   # legacy v0.1 mode
"""
import json
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

from bs4 import BeautifulSoup, Comment

## --------------------------------------------------------------------
## HTTP header normalisation. The capture stores full response headers
## per URL; volatile values (timestamps, request ids, cache hits) are
## scrubbed so the diff focuses on header VALUES that matter for
## behaviour (Cache-Control, Content-Security-Policy, X-Frame-Options,
## ...) rather than per-request flake.
## --------------------------------------------------------------------

VOLATILE_HEADERS = {
    "date",
    "age",
    "x-served-by",
    "x-cache",
    "x-cache-status",
    "x-cache-hits",
    "x-request-id",
    "request-id",
    "x-trace-id",
    "x-runtime",
    "x-response-time",
    "x-backend-response-time",
    "x-backend-date",
    "last-modified",
    "expires",
}

## Headers whose value contains a URL that may itself have a volatile
## query string. e.g. onion-location reflects the request URL with all
## its cache-busters.
URL_VALUED_HEADERS = ("onion-location", "link", "location", "content-location")

## Headers whose values are stable when scrubbed of their per-build
## random-token bits.
HEADER_TOKEN_PATTERNS = [
    ## Content-Security-Policy nonces look like nonce-XXXXX; the
    ## token rotates per response. Other policy directives are stable.
    ("content-security-policy", re.compile(r"nonce-[A-Za-z0-9+/=]+"), "nonce-SCRUBBED"),
    ## ETags often contain content hashes that are stable; the
    ## weak-marker and quotes vary across CDN tiers, so trim them.
    ("etag", re.compile(r"\s+"), ""),
]


## --------------------------------------------------------------------
## Per-request volatility we always want to strip.
## --------------------------------------------------------------------

VOLATILE_COMMENT_PATTERNS = [
    re.compile(r"NewPP limit report", re.I),
    re.compile(r"Transclusion expansion time report", re.I),
    re.compile(r"Saved in parser cache", re.I),
    re.compile(r"\bServed by\b", re.I),
    re.compile(r"\bCached time:", re.I),
    re.compile(r"\bCache expiry:", re.I),
    re.compile(r"\bRendering timestamp:", re.I),
    re.compile(r"\bCPU time usage:", re.I),
    re.compile(r"\bReal time usage:", re.I),
    re.compile(r"\bPreprocessor (visited|generated) node count", re.I),
    re.compile(r"\bPost.expand include size", re.I),
    re.compile(r"\bTemplate argument size", re.I),
    re.compile(r"\bHighest expansion depth", re.I),
    re.compile(r"\bExpensive parser function count", re.I),
    re.compile(r"\bUnstrip recursion depth", re.I),
    re.compile(r"\bUnstrip post.expand size", re.I),
    re.compile(r"Lua time usage:", re.I),
    re.compile(r"Lua memory usage:", re.I),
]

VOLATILE_ATTRS = {"nonce"}

## Query-string parameters whose values are pure cache-busters.
## Scrubbing keeps URL diffs focused on "what changed structurally"
## (a new module set) rather than "what was the build version".
VOLATILE_QUERY_PARAMS = {
    "version",                                  ## MW ResourceLoader
    "_",                                        ## jQuery cache buster
    "epoch",
    "t",
    "hsversion-headscript-replacement-by-server",
    "hsversion_from_server_replacement_unixtime",
}

VOLATILE_MW_CONFIG_KEYS = [
    "wgRequestId",
    "wgBackendResponseTime",
    "wgCSPNonce",
    "wgCacheEpoch",
    "wgInternalRedirectTargetUrl",
    "wgUserEditCount",
    "wgUserRegistration",
]

VOLATILE_JSON_KEYS = ["dateModified", "datePublished"]

## mw.user.tokens.set({...}) emits these per-session tokens that
## rotate every login.
VOLATILE_USER_TOKEN_KEYS = ["patrolToken", "watchToken", "csrfToken"]

VOLATILE_META_PROPERTIES = {
    "article:modified_time",
    "article:published_time",
    "og:updated_time",
}

LAZY_INJECTED_STYLE_FINGERPRINTS = [
    re.compile(r"\bmwe-popups\b"),
    re.compile(r"\bmwe-popups-"),
    re.compile(r"\.popups-icon--"),
    re.compile(r"\.mw-mmv-"),
    re.compile(r"\.cite-accessibility-label"),
    re.compile(r"\.cite-reference-preview"),
]

URL_ATTRS = ("href", "src", "data-src", "action", "data-href", "srcset")


def _normalize_url(value: str) -> str:
    if not isinstance(value, str) or "?" not in value:
        return value
    try:
        p = urlparse(value)
    except ValueError:
        return value
    if not p.query:
        return value
    params = parse_qsl(p.query, keep_blank_values=True)
    rebuilt = []
    for k, v in params:
        if k in VOLATILE_QUERY_PARAMS:
            v = "SCRUBBED"
        elif k == "modules" and v:
            v = "|".join(sorted(v.split("|")))
        rebuilt.append((k, v))
    rebuilt.sort()
    return p._replace(query=urlencode(rebuilt, safe="|:")).geturl()


def _normalize_srcset(value: str) -> str:
    if not isinstance(value, str) or "," not in value:
        return _normalize_url(value)
    parts = []
    for item in value.split(","):
        item = item.strip()
        if " " in item:
            u, d = item.split(" ", 1)
            parts.append(f"{_normalize_url(u)} {d}")
        else:
            parts.append(_normalize_url(item))
    return ", ".join(parts)


def _scrub_script_text(text: str) -> str:
    for key in (*VOLATILE_MW_CONFIG_KEYS, *VOLATILE_JSON_KEYS, *VOLATILE_USER_TOKEN_KEYS):
        text = re.sub(
            rf'"{re.escape(key)}"\s*:\s*("[^"]*"|-?\d+(?:\.\d+)?|true|false|null)',
            f'"{key}":"SCRUBBED"',
            text,
        )
    text = re.sub(r'"version"\s*:\s*"[0-9a-f]{6,}"', '"version":"SCRUBBED"', text)
    return text


## JS-generated random element ids used by TabContentController and
## similar (data-tcc-contentid, id, href fragment). All look like
## "id-" followed by 14+ decimal digits; the digits are reseeded
## every page load.
RANDOM_ID_RE = re.compile(r"\bid-\d{10,}\b")


def normalize_html(html: str) -> str:
    ## Scrub JS-generated random ids early so the BeautifulSoup parse
    ## sees the canonical form. Safer to do this on the string than
    ## inside the tree walk since the ids appear both as attribute
    ## values AND inside href fragments and inline script bodies.
    html = RANDOM_ID_RE.sub("id-SCRUBBED", html)

    soup = BeautifulSoup(html, "lxml")

    for c in list(soup.find_all(string=lambda t: isinstance(t, Comment))):
        text = str(c)
        if any(p.search(text) for p in VOLATILE_COMMENT_PATTERNS):
            c.extract()

    ## #back-to-top-button fades in/out on scroll. Even with our
    ## animation/transition CSS override at capture time the inline
    ## style="opacity: ..." value can land at 0.999973 vs 1.000 vs
    ## 0.96... across runs depending on exactly when the snapshot is
    ## taken. The button's existence is observable; the in-flight
    ## opacity isn't. Drop the inline style entirely.
    btn = soup.find(id="back-to-top-button")
    if btn and btn.get("style"):
        del btn.attrs["style"]

    ## #mw-teleport-target is an empty slot the Vector skin creates
    ## lazily via JS for popover content. It's present or absent
    ## depending on which RL modules raced to the front of the queue
    ## at networkidle time. Drop it -- it's structurally empty.
    tt = soup.find(id="mw-teleport-target")
    if tt and not tt.contents:
        tt.decompose()

    for tag in soup.find_all(True):
        if tag.name == "meta" and tag.get("property") in VOLATILE_META_PROPERTIES:
            tag["content"] = "SCRUBBED"
        attrs = tag.attrs
        for attr_name in list(attrs.keys()):
            value = attrs[attr_name]
            if attr_name in VOLATILE_ATTRS:
                attrs[attr_name] = "SCRUBBED"
                continue
            if attr_name == "srcset" and isinstance(value, str):
                attrs[attr_name] = _normalize_srcset(value)
            elif attr_name in URL_ATTRS and isinstance(value, str):
                attrs[attr_name] = _normalize_url(value)
            elif isinstance(value, list):
                attrs[attr_name] = sorted(value)
        tag.attrs = dict(sorted(attrs.items()))

    for script in soup.find_all("script"):
        if script.string:
            script.string.replace_with(_scrub_script_text(str(script.string)))

    for style in soup.find_all("style"):
        text = style.string or ""
        if any(p.search(text) for p in LAZY_INJECTED_STYLE_FINGERPRINTS):
            style.decompose()

    for a in list(soup.find_all("a")):
        if a.string and a.string.strip() == "Edit preview settings":
            ancestor = a.find_parent("li") or a
            ancestor.decompose()

    return soup.prettify(formatter="minimal")


def _normalize_headers(headers: dict) -> dict:
    out = {}
    for name, value in (headers or {}).items():
        n = name.lower()
        if n in VOLATILE_HEADERS:
            out[n] = "SCRUBBED"
            continue
        v = value
        for header_name, pattern, replacement in HEADER_TOKEN_PATTERNS:
            if n == header_name:
                v = pattern.sub(replacement, v)
        if n in URL_VALUED_HEADERS:
            v = _normalize_url(v)
        out[n] = v
    return dict(sorted(out.items()))


def normalize_manifest(manifest: dict, page_url: str | None = None) -> dict:
    """Strip volatile query params, drop timing-flake entries, and
    normalise the headers dict per entry. Sort by URL for stable
    output.
    """
    out: dict[str, dict] = {}
    for url, entry in manifest.items():
        if entry.get("status") == 404:
            continue
        if page_url and url.startswith(page_url):
            continue
        nurl = _normalize_url(url)
        normalised_entry = dict(entry)
        if "headers" in normalised_entry:
            normalised_entry["headers"] = _normalize_headers(normalised_entry["headers"])
        out.setdefault(nurl, normalised_entry)
    return dict(sorted(out.items()))


def normalize_page_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)

    html = (src / "dom.html").read_text(encoding="utf-8")
    (dst / "dom.html").write_text(normalize_html(html), encoding="utf-8")

    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    ## Infer the wiki page URL from the manifest. The first text/html
    ## 200 entry is by construction the navigation target.
    page_url = None
    for url, entry in manifest.items():
        if entry.get("status") == 200 and entry.get("content_type", "").startswith("text/html"):
            page_url = url
            break
    nm = normalize_manifest(manifest, page_url)
    (dst / "manifest.json").write_text(
        json.dumps(nm, indent=2, sort_keys=True), encoding="utf-8"
    )

    ## Screenshot: copy as-is. Pixel-diff is the comparison step.
    screenshot_src = src / "screenshot.png"
    if screenshot_src.exists():
        shutil.copy2(screenshot_src, dst / "screenshot.png")

    ## Assets are content-hashed so already canonical; rsync-like
    ## mirror so the dst layout is self-contained.
    src_assets = src / "assets"
    dst_assets = dst / "assets"
    if src_assets.exists():
        dst_assets.mkdir(exist_ok=True)
        for f in src_assets.iterdir():
            target = dst_assets / f.name
            if not target.exists():
                shutil.copy2(f, target)


def _legacy_html_mode(src: Path, dst: Path) -> int:
    """Backwards compatible with v0.1: input is a single HTML file."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(normalize_html(src.read_text(encoding="utf-8")), encoding="utf-8")
    return 0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: normalize.py <input> <output>", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    if src.is_dir():
        ## If src contains nested mode subdirs (anon-first/, anon-repeat/,
        ## user-first/, user-repeat/) iterate them. Otherwise treat src
        ## itself as a single per-page snapshot dir for backwards compat.
        nested = [p for p in src.iterdir() if p.is_dir() and (p / "dom.html").exists()]
        if nested:
            for mode_dir in nested:
                normalize_page_dir(mode_dir, dst / mode_dir.name)
            return 0
        if (src / "dom.html").exists():
            normalize_page_dir(src, dst)
            return 0
    if src.is_file() and src.suffix == ".html":
        return _legacy_html_mode(src, dst)
    print(f"normalize.py: don't know how to normalise {src}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
