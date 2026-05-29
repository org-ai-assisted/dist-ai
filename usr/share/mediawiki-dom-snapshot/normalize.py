#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Rewrite a raw rendered HTML dump into a stable, diff-friendly form.

Removes per-request volatility (CSP nonces, cache timestamps,
ResourceLoader version hashes, request IDs, lazy-injected styles, ...)
and pretty-prints with sorted attributes so byte-level diffs surface
only meaningful changes.

Usage:  normalize.py <input.html> <output.html>
"""
import re
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

from bs4 import BeautifulSoup, Comment

## --------------------------------------------------------------------
## Per-request volatility we always want to strip.
## --------------------------------------------------------------------

## Comments that MediaWiki, parser cache, Varnish/nginx, etc. inject with
## timestamps or per-request values. Match anywhere in the comment text.
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

## Attributes whose value is replaced with a fixed placeholder.
VOLATILE_ATTRS = {
    "nonce",          ## CSP per-response nonce
}

## Query-string parameters in <link>/<script>/<img> URLs whose values
## change every build but don't affect identity (cache-busters,
## ResourceLoader hashes).
VOLATILE_QUERY_PARAMS = {"version", "_", "epoch", "t"}

## mw.config.set keys with per-request / per-session values.
VOLATILE_MW_CONFIG_KEYS = [
    "wgRequestId",
    "wgBackendResponseTime",
    "wgCSPNonce",
    "wgCacheEpoch",
    "wgInternalRedirectTargetUrl",  ## contains tokens occasionally
    "wgUserEditCount",              ## changes anytime someone edits
    "wgUserRegistration",
]

## JSON-LD / OpenGraph fields whose values are the current request time
## on pages that have no real article timestamp (Special:* etc.).
VOLATILE_JSON_KEYS = [
    "dateModified",
    "datePublished",
]

## <meta property="..."> whose content is the request time on Special pages.
VOLATILE_META_PROPERTIES = {
    "article:modified_time",
    "article:published_time",
    "og:updated_time",
}

## Inline <style> blocks injected by lazy ResourceLoader modules (Popups
## on hover, MediaViewer on click, Cite reference-preview, ...). These
## are fingerprinted by class-name fragments unique to each module. We
## drop the tags entirely: their inclusion is timing-dependent (race
## between snapshot and module first-execution) which breaks
## reproducibility. To detect upgrades to these modules' CSS, watch the
## corresponding load.php URL in <link rel="stylesheet"> -- the version=
## query param tracks content hash.
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
    """Sort `modules=A|B|C` alphabetically and scrub volatile query params."""
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
    """srcset is "url descriptor, url descriptor, ..."."""
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
    """Replace volatile values inside mw.config.set / RLQ / JSON-LD blobs."""
    for key in (*VOLATILE_MW_CONFIG_KEYS, *VOLATILE_JSON_KEYS):
        text = re.sub(
            rf'"{re.escape(key)}"\s*:\s*("[^"]*"|-?\d+(?:\.\d+)?|true|false|null)',
            f'"{key}":"SCRUBBED"',
            text,
        )
    ## ResourceLoader inline startup module embeds a `version` hash per module.
    text = re.sub(r'"version"\s*:\s*"[0-9a-f]{6,}"', '"version":"SCRUBBED"', text)
    return text


def normalize_html(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")

    ## Drop volatile comments.
    for c in list(soup.find_all(string=lambda t: isinstance(t, Comment))):
        text = str(c)
        if any(p.search(text) for p in VOLATILE_COMMENT_PATTERNS):
            c.extract()

    ## Walk every tag once: rewrite URL attrs, scrub volatile attrs, sort.
    for tag in soup.find_all(True):
        ## <meta property="article:modified_time" content="...">: scrub.
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
                ## BS treats some attrs as lists (e.g. class). Sort for
                ## stable diffs.
                attrs[attr_name] = sorted(value)
        tag.attrs = dict(sorted(attrs.items()))

    ## Rewrite inline scripts to scrub volatile values inside JSON blobs.
    for script in soup.find_all("script"):
        if script.string:
            script.string.replace_with(_scrub_script_text(str(script.string)))

    ## Drop inline <style> blocks that lazy-loaded modules inject after
    ## interaction (Popups on hover, MediaViewer on click, ...). Their
    ## presence is timing-dependent across runs.
    for style in soup.find_all("style"):
        text = style.string or ""
        if any(p.search(text) for p in LAZY_INJECTED_STYLE_FINGERPRINTS):
            style.decompose()

    ## Same flake source: Popups' user-portlet "Edit preview settings"
    ## entry gets injected only when the module has run. Drop it.
    for a in list(soup.find_all("a")):
        if a.string and a.string.strip() == "Edit preview settings":
            ancestor = a.find_parent("li") or a
            ancestor.decompose()

    return soup.prettify(formatter="minimal")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: normalize.py <input.html> <output.html>", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(normalize_html(src.read_text(encoding="utf-8")), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
