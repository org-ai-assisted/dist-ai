#!/usr/bin/python3 -Bsu
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
import hashlib
import json
import os
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
    "etag",        ## MW embeds the ResourceLoader version hash in the ETag;
                   ## rotates per server build with no content change.
}

## Headers whose value contains a URL that may itself have a volatile
## query string. e.g. onion-location reflects the request URL with all
## its cache-busters.
URL_VALUED_HEADERS = (
    "onion-location",
    "link",
    "location",
    "content-location",
    "sourcemap",   ## MW serves sourcemap URLs with the same per-build
                   ## version token as the ResourceLoader startup body.
)

## Headers whose values are stable when scrubbed of their per-build
## random-token bits.
HEADER_TOKEN_PATTERNS = [
    ## Content-Security-Policy nonces look like nonce-XXXXX; the
    ## token rotates per response. Other policy directives are stable.
    ("content-security-policy", re.compile(r"nonce-[A-Za-z0-9+/=]+"), "nonce-SCRUBBED"),
    ## ETags often contain content hashes that are stable; the
    ## weak-marker and quotes vary across CDN tiers, so trim them.
    ("etag", re.compile(r"\s+"), ""),
    ## Varnish/CDN s-maxage on parser-cached pages counts down toward
    ## the page's next refresh; the seconds-remaining drifts between
    ## captures. The directive's PRESENCE is stable; scrub the number.
    ## Keep max-age (driven by Cache-Control config, not a countdown).
    ("cache-control", re.compile(r"s-maxage=\d+"), "s-maxage=SCRUBBED"),
    ("x-backend-cache-control", re.compile(r"s-maxage=\d+"), "s-maxage=SCRUBBED"),
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
    ## Revision ids are database row ids assigned at page-save time. When
    ## the same logical content is imported/re-saved into two separate
    ## wiki instances (or batch-reloaded), each side mints its own
    ## sequential revision ids, so the SAME page text carries a different
    ## wgRevisionId / wgCurRevisionId / wgStableRevisionId per capture.
    ## The id is RLCONF metadata, never reader-facing -- any genuine
    ## content change still surfaces in the rendered DOM body -- so the
    ## bare id delta is pure batch-load noise. Scrub it.
    "wgRevisionId",
    "wgCurRevisionId",
    "wgStableRevisionId",
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
    re.compile(r"\.mw-portlet-dock-bottom"),
    re.compile(r"#mw-teleport-target"),
    ## Search box autocomplete widget. The styles are injected only
    ## once the user opens the title-suggest dropdown, which we
    ## sometimes trigger by typing into Special:Search and sometimes
    ## don't reach in time.
    re.compile(r"\.mw-widget-titleWidget"),
    re.compile(r"\.mw-widget-titleOptionWidget"),
    ## Edit page widget modules: edit-footer toggler, preview spinner,
    ## edit-form helpers, wikiEditor toolbar/dialogs. Lazy-loaded by
    ## action=edit JS when the form reaches interactive state. Same
    ## race vs networkidle.
    re.compile(r"\.mw-editfooter-"),
    re.compile(r"\.mw-editform"),
    re.compile(r"\.mw-preview-loading-elements"),
    re.compile(r"\.mw-wikiEditor-"),
    re.compile(r"\.wikiEditor-ui"),
    re.compile(r"\.wikiEditor-toolbar"),
    re.compile(r"\.wikieditor-toolbar"),
]

## ResourceLoader module names are emitted as "name@VERSION" in the
## bundled JS body where VERSION is a 4-5 char alphanumeric that
## rotates per server build with no module content change. Same
## per-build noise as the startup module body.
MODULE_VERSION_RE = re.compile(r'("[\w.-]+)@[a-z0-9]{4,8}(")')

URL_ATTRS = ("href", "src", "data-src", "action", "data-href", "srcset")

## --------------------------------------------------------------------
## HTML whitespace canonicalisation.
##
## The Smarty (Extension:Widgets) backend and the PHP-parser-function
## backend emit the SAME semantic DOM but with different *incidental*
## whitespace: the Smarty path leaves behind empty <p></p> (and MW's
## <p class="mw-empty-elt"></p>) paragraphs, spreads HTML comments
## across several indented lines, and pads text nodes with extra
## spaces / newlines. None of that is observable -- the browser
## collapses runs of whitespace in normal flow and never renders empty
## paragraphs or comments -- so it is pure formatting churn that
## otherwise drowns the diff. Canonicalise it.
##
## CONSERVATIVE: whitespace is significant inside <pre>/<code>/
## <textarea>/<script>/<style>, so text nodes anywhere beneath those
## tags are left byte-for-byte untouched. Only truly empty paragraphs
## are dropped, and a <p> carrying an id (a possible anchor target) is
## always kept. Semantic content (any non-whitespace text) is never
## altered beyond collapsing internal whitespace runs to one space,
## which is exactly what HTML rendering does.
## --------------------------------------------------------------------
WHITESPACE_SENSITIVE_TAGS = {"pre", "code", "textarea", "script", "style"}
_WS_RUN_RE = re.compile(r"\s+")


def _whitespace_sensitive_string_ids(soup) -> set:
    ## id() of every string node that has a whitespace-sensitive ancestor, in ONE O(N)
    ## pass. An EXPLICIT stack carries each element's count of whitespace-sensitive
    ## ancestors (a string node is sensitive when that count > 0); recursion is avoided so
    ## an adversarially deep tree cannot blow the interpreter's recursion limit. Must not
    ## itself amplify: a find_all(WHITESPACE_SENSITIVE_TAGS) then find_all(string) PER tag
    ## re-walks each subtree, which is O(depth^2) for nested <pre>/<code> -- the same DoS
    ## class this runs ahead of the prettify cap to avoid. A single stacked descent is O(N)
    ## regardless of nesting. Membership is equivalent to "any ancestor is a pre/code/
    ## textarea/script/style".
    sensitive = set()
    stack = [(soup, 0)]
    while stack:
        node, depth = stack.pop()
        for child in node.children:
            name = getattr(child, "name", None)
            if name is None:
                ## a string node (NavigableString/Comment): sensitive iff under a
                ## whitespace-sensitive ancestor
                if depth > 0:
                    sensitive.add(id(child))
            else:
                stack.append(
                    (child, depth + (1 if name in WHITESPACE_SENSITIVE_TAGS else 0)))
    return sensitive


def _canonicalise_whitespace(soup) -> None:
    ## Drop empty paragraphs (Smarty leaves <p></p> and MW emits
    ## <p class="mw-empty-elt"></p>); both render nothing. Keep any <p>
    ## that has element children, non-whitespace text, or an id anchor.
    for p in soup.find_all("p"):
        if p.get("id"):
            continue
        if p.find(True) is not None:
            continue
        if p.get_text(strip=True):
            continue
        ## Keep an empty <p> that still carries VISIBLE styling -- a style attribute, or a
        ## class other than MW's mw-empty-elt noise marker -- since it can occupy layout
        ## (e.g. <p class="banner" style="height:100px">), a real render difference the
        ## snapshot must not hide. Only the truly inert / mw-empty-elt paragraphs are noise.
        classes = p.get("class") or []
        if p.get("style") or (set(classes) - {"mw-empty-elt"}):
            continue
        p.decompose()

    ## Collapse whitespace runs inside the HTML comments we keep, so a
    ## multi-line indented comment in one backend matches the same
    ## comment serialised on a single line in the other. Comments are
    ## never rendered, so this is safe.
    for c in list(soup.find_all(string=lambda t: isinstance(t, Comment))):
        original = str(c)
        collapsed = _WS_RUN_RE.sub(" ", original).strip()
        if collapsed != original:
            c.replace_with(Comment(collapsed))

    ## Collapse whitespace runs in text nodes outside whitespace-
    ## sensitive elements. A run of spaces/newlines/tabs becomes a
    ## single space -- identical to how the browser lays the text out.
    sensitive_ids = _whitespace_sensitive_string_ids(soup)
    for t in list(soup.find_all(string=True)):
        if isinstance(t, Comment):
            continue
        if id(t) in sensitive_ids:
            continue
        original = str(t)
        collapsed = _WS_RUN_RE.sub(" ", original)
        if collapsed != original:
            t.replace_with(collapsed)


def _normalize_url(value: str) -> str:
    if not isinstance(value, str) or "?" not in value:
        return value
    try:
        p = urlparse(value)
    except ValueError:
        return value
    ## Only hierarchical http(s) URLs (and scheme-relative / relative ones, scheme='')
    ## use '?' as a query delimiter. An OPAQUE scheme (data:/javascript:/mailto:/tel:/
    ## blob:) can carry a literal '?' that is NOT a query -- treating it as one (parse_qsl
    ## + re-encode) corrupts the payload (percent-escaping </script> etc.) and yields a
    ## spurious/masked diff. Leave a present, non-http(s) scheme untouched.
    if p.scheme and p.scheme not in ("http", "https"):
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
    ## Split on the CANDIDATE boundary (a comma followed by whitespace before the next
    ## candidate), NOT a bare comma: a comma is legal inside a URL query (RFC 3986
    ## sub-delim) AND mandatory in a data: URI ("...;base64,AAAA"), so value.split(",")
    ## shreds those. A boundary comma is conventionally followed by whitespace; an in-URL
    ## comma is followed by data (no space), so it is preserved and its candidate reaches
    ## _normalize_url whole (which already passes an opaque data:/javascript: scheme
    ## through untouched).
    for item in re.split(r",\s+(?=\S)", value):
        item = item.strip()
        if not item:
            continue
        if " " in item:
            u, d = item.split(" ", 1)
            parts.append(f"{_normalize_url(u)} {d}")
        else:
            parts.append(_normalize_url(item))
    return ", ".join(parts)


def _scrub_script_text(text: str) -> str:
    for key in (*VOLATILE_MW_CONFIG_KEYS, *VOLATILE_JSON_KEYS, *VOLATILE_USER_TOKEN_KEYS):
        ## The value alternative matches a proper JSON string (allowing an escaped
        ## `\"` inside it) so a token like "ab\"cd1234" is scrubbed WHOLE; a plain
        ## `"[^"]*"` would stop at the escaped quote and leak the tail.
        text = re.sub(
            rf'"{re.escape(key)}"\s*:\s*("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?|true|false|null)',
            f'"{key}":"SCRUBBED"',
            text,
        )
    text = re.sub(r'"version"\s*:\s*"[0-9a-f]{6,}"', '"version":"SCRUBBED"', text)
    ## mw.user.options.set({...}); gets populated by MediaWiki after the
    ## first user-mode visit and persists; subsequent captures see
    ## entries the first capture wrote (rcfilters-limit, rcfilters-
    ## saved-queries, ...) -- and a capture against a freshly-created
    ## user has the call ABSENT entirely while a later capture has it
    ## PRESENT. Drop the entire statement (including the trailing
    ## semicolon) so present-or-absent stops mattering.
    ## String-aware body match: skip quoted string values (with escapes) so a literal
    ## "});" INSIDE a value cannot truncate the match early and leave malformed trailing
    ## JS. Stops at the first REAL (unquoted) object close. MW emits a flat object here.
    text = re.sub(
        r"""mw\.user\.options\.set\(\{(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^"'}])*\}\);?""",
        "",
        text,
    )
    return text


## JS-generated random element ids. Multiple flavours; each pattern is
## a (regex, replacement) pair scrubbed in-place before the soup parse.
## Doing this on the string layer is safer than per-attribute because
## the ids also appear inside aria-controls fragments and inline JS.
##
##   id-NNNNNNNNNN   TabContentController and similar; 10+ decimal digits
##   html5_BASE36    Plupload/moxie file-shim container; ~28 base36 chars
##   menu-NNNNNN     wikieditor menus; epoch-millis used as id
RANDOM_ID_PATTERNS = (
    (re.compile(r"\bid-\d{10,}\b"), "id-SCRUBBED"),
    ## No trailing \b: the moxie shim emits BOTH "html5_<rand>" and
    ## "html5_<rand>_container", so we want a non-greedy stop at the
    ## first non-base36 char rather than requiring a word boundary
    ## (underscore is a word char and would defeat \b).
    (re.compile(r"html5_[0-9a-z]{20,}"), "html5_SCRUBBED"),
    (re.compile(r"\bmenu-\d{10,}\b"), "menu-SCRUBBED"),
)

## Edit-form hidden inputs whose value rotates per edit session. They
## appear as <input name="..." value="..."> in action=edit pages.
##   wpStarttime      14-digit timestamp of when the editor was opened
##   wpEdittime       14-digit timestamp of the latest revision -- stable
##                    across captures of the same wiki state but rotates
##                    once any edit happens; safe to scrub
##   wpEditToken      40 hex + "+\" CSRF token, rotates per session
VOLATILE_INPUT_NAMES = {"wpStarttime", "wpEdittime", "wpEditToken"}

## Cross-wiki host scrub. A before/after diff served on DIFFERENT hostnames
## (e.g. old.whonix.org vs www.whonix.org) would otherwise flag every absolute
## URL, canonical link, og:url and JS wgServer. Set DOM_DIFF_HOST_SCRUB to a
## comma-separated list of hostnames; each is collapsed to a single placeholder
## across every surface a diff compares -- the raw HTML, text asset bodies
## (CSS/JS/SVG/JSON), manifest URL keys, response header values, cookie/storage
## values, console + errors message text, and the verbatim JSON copies (computed_
## styles/hover_styles/iframes_shadow) -- so only real content deltas survive and
## the true host never leaks. Empty (the default) is a no-op (same-host diffs).
## Sort LONGEST host first so the per-host substitutions are applied longest-match-
## first. A shorter host that is a substring of a longer one (apex "test.invalid" vs
## subdomain "old.test.invalid") would otherwise, if listed first, consume the inner
## "test.invalid" out of the longer occurrence and leave a real-host fragment ("old.")
## behind. Longest-first guarantees the enclosing host collapses whole before any
## shorter substring can bite into it. Both compiled tuples below inherit this order.
HOST_SCRUB = tuple(
    sorted(
        (h.strip() for h in os.environ.get("DOM_DIFF_HOST_SCRUB", "").split(",") if h.strip()),
        key=len,
        reverse=True,
    )
)
HOST_SCRUB_PLACEHOLDER = "wiki-host.invalid"

## Case-insensitive literal match: re.escape keeps only the host substring
## in scope so scheme/path bytes stay intact; IGNORECASE catches Old.Test vs
## old.test host casings that a plain str.replace would miss.
_HOST_SCRUB_RES = tuple(re.compile(re.escape(h), re.IGNORECASE) for h in HOST_SCRUB)


def _scrub_hosts(text):
    if not isinstance(text, str):
        return text
    for pat in _HOST_SCRUB_RES:
        text = pat.sub(HOST_SCRUB_PLACEHOLDER, text)
    return text


## Byte-level host scrub for an asset whose content_type does NOT prove it text
## (the else branch of the asset loop). content_type is UNTRUSTED, so a mislabeled
## text body (css as application/octet-stream, omitted, or mixed-case) would else
## copy through verbatim and LEAK the host. Scrubbing at the byte level fails CLOSED
## for such a body, and a genuine binary (no host bytes) is left bit-identical with
## no lossy UTF-8 round-trip.
_HOST_SCRUB_RES_BYTES = tuple(
    re.compile(re.escape(h.encode("utf-8")), re.IGNORECASE) for h in HOST_SCRUB
)


def _scrub_hosts_bytes(data):
    for pat in _HOST_SCRUB_RES_BYTES:
        data = pat.sub(HOST_SCRUB_PLACEHOLDER.encode("utf-8"), data)
    return data


def _is_text_asset(content_type: str) -> bool:
    ## Text-shaped asset bodies (CSS, JS, SVG, JSON) can embed absolute URLs to the
    ## wiki host; binary assets (images, fonts) cannot, so they copy through untouched.
    ct = content_type.lower()   ## media types are case-insensitive (RFC 7231)
    return (
        ct.startswith(("text/", "application/javascript", "application/json"))
        or "svg" in ct
    )


## soup.prettify() indents proportionally to nesting depth, so its output is O(N x depth):
## a small (few-hundred-KB) but pathologically deep untrusted dom.html amplifies to GBs and
## exhausts the diff host. Past these bounds fall back to the O(N) compact serialisation.
_MAX_HTML_DEPTH = 500          ## real MediaWiki pages nest far shallower
_MAX_HTML_INPUT = 20_000_000   ## 20 MB; a page over this is pathological


def _nesting_depth_exceeds(node, limit):
    ## Iterative DFS with an early bail: returns True as soon as ANY branch passes `limit`,
    ## so a pathologically deep tree costs O(limit), not O(N x depth).
    stack = [(node, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > limit:
            return True
        for child in getattr(cur, "children", ()):
            if getattr(child, "name", None):
                stack.append((child, depth + 1))
    return False


def normalize_html(html: str) -> str:
    html = _scrub_hosts(html)
    ## Untrusted-input DoS cap comes FIRST, before ANY tree processing. dom.html is
    ## attacker-controllable and several passes below cost more than O(N) on a
    ## pathologically large or deep tree (prettify's O(N*depth) indent worst of all).
    ## Gating everything behind the cap keeps the invariant that no code path can amplify
    ## ahead of it -- the earlier a new pass is added, the easier it is to slip in above a
    ## cap placed lower down. Host-scrub (the security transform) has already run on the
    ## string above, so the fallbacks below are safe; only diff-stability canonicalisation
    ## is skipped for a page this degenerate.
    if len(html) > _MAX_HTML_INPUT:
        return html
    ## Scrub JS-generated random ids early so the BeautifulSoup parse
    ## sees the canonical form. Safer to do this on the string than
    ## inside the tree walk since the ids appear both as attribute
    ## values AND inside href fragments and inline script bodies.
    for pat, repl in RANDOM_ID_PATTERNS:
        html = pat.sub(repl, html)

    soup = BeautifulSoup(html, "lxml")

    ## Depth arm of the cap, immediately after the parse and before every depth-amplifiable
    ## pass (whitespace canonicalisation, prettify). _nesting_depth_exceeds is an
    ## O(depth-limit) early-bail, so the probe is cheap; str(soup) is the compact O(N)
    ## serialisation of the already-host-scrubbed tree.
    if _nesting_depth_exceeds(soup, _MAX_HTML_DEPTH):
        return str(soup)

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

    ## #fly-in-notification-panel: JS reads its computed width and
    ## writes it back as inline style="width: 299.187px; overflow:
    ## hidden;" -- the value jitters subpixel between runs, and the
    ## *presence* of the style mutation races networkidle so one
    ## capture has it and another doesn't. The panel CSS is the
    ## source of truth; drop the JS-applied inline style on both the
    ## panel and its .inner-wrapper child.
    panel = soup.find(id="fly-in-notification-panel")
    if panel:
        if panel.get("style"):
            del panel.attrs["style"]
        wrapper = panel.find(class_="inner-wrapper")
        if wrapper and wrapper.get("style"):
            del wrapper.attrs["style"]

    ## Splide carousels (Homepage feature reel etc): the autoplay
    ## advances the active slide every couple of seconds, so each
    ## capture sees a different translateX, a different active dot,
    ## and a different "30 of 35" aria-label. The carousel's identity
    ## is still observable (number of slides, slide content, library
    ## init markers); the in-flight scroll position isn't. Drop the
    ## dynamic state: translateX inline style, transition on the
    ## list, is-active class + aria-selected on pagination buttons.
    for sl in soup.find_all(class_="splide__list"):
        if sl.get("style"):
            del sl.attrs["style"]
    for sec in soup.find_all(class_="splide"):
        for cls in ("is-active", "is-initialized", "is-overflow"):
            classes = sec.get("class") or []
            if cls in classes:
                classes = [c for c in classes if c != cls]
                sec["class"] = classes
    ## .splide__track carries aria-busy={"true"|"false"} reflecting
    ## the in-flight scroll animation. We've already paused the
    ## animation in snapshot.py, but the attribute occasionally
    ## flickers depending on the order events fire. Drop it.
    for tr in soup.find_all(class_="splide__track"):
        if "aria-busy" in tr.attrs:
            del tr.attrs["aria-busy"]
    for btn in soup.find_all(class_="splide__pagination__page"):
        classes = btn.get("class") or []
        classes = [c for c in classes if c != "is-active"]
        btn["class"] = classes
        for attr in ("aria-selected", "tabindex"):
            if attr in btn.attrs:
                del btn.attrs[attr]
    ## Individual slides carry is-active / is-prev / is-next /
    ## is-visible based on where the loop pointer currently is.
    ## All four jitter; strip them. The screen-reader visibility
    ## attributes (aria-hidden, tabindex on the slide's anchor) flip
    ## with the same loop state, so strip them too.
    for slide in soup.find_all(class_="splide__slide"):
        classes = slide.get("class") or []
        classes = [
            c for c in classes
            if c not in ("is-active", "is-prev", "is-next", "is-visible")
        ]
        slide["class"] = classes
        if "aria-hidden" in slide.attrs:
            del slide.attrs["aria-hidden"]
        for desc in slide.find_all(["a", "button"]):
            if desc.get("tabindex") == "-1":
                del desc.attrs["tabindex"]
    for clone in soup.find_all(class_="splide__slide--clone"):
        ## "30 of 35" / "31 of 35" labels point at where in the loop
        ## we are; loop position rotates per capture. Strip.
        if clone.get("aria-label"):
            del clone.attrs["aria-label"]

    ## .header-menu.nav-menu carries an "active" class added by the
    ## skin JS once scroll lock kicks in (mobile menu open vs closed
    ## state races networkidle).
    for hm in soup.find_all(class_="header-menu"):
        classes = hm.get("class") or []
        if "active" in classes:
            hm["class"] = [c for c in classes if c != "active"]

    ## #t-collapsible-toggle-all is an "Expand all collapsible
    ## elements" menu item added by an extension when the page has
    ## collapsibles AND the JS catches them before networkidle. The
    ## menu item's *presence* is racy; drop it.
    for tog in soup.find_all(id="t-collapsible-toggle-all"):
        tog.decompose()

    ## .editor-auto-backup icon: a save-icon glyph added to the edit
    ## toolbar by the autosave extension once it picks up the form.
    ## The race against networkidle decides whether the icon (and the
    ## fa-regular webfont it forces to load) appears.
    for icon in soup.find_all(class_="editor-auto-backup"):
        icon.decompose()

    ## .editor-fullscreen toggle group (open + close fullscreen icons)
    ## injected by the wikieditor fullscreen extension once it
    ## activates. Same race vs networkidle.
    for el in soup.find_all(class_="editor-fullscreen"):
        el.decompose()

    ## .moxie-shim is the Plupload file-input wrapper. Its inline
    ## style includes top/left/width/height computed from layout that
    ## shifts when other JS-injected widgets (auto-backup icon etc)
    ## arrive at different points in time. The shim is a transparent
    ## interaction target -- the positioning isn't observable. Drop
    ## the inline style.
    for shim in soup.find_all(class_=re.compile(r"^moxie-shim")):
        if shim.get("style"):
            del shim.attrs["style"]

    ## .code-select (copy-to-clipboard wrapper) computes its own
    ## scrollbar viewport height + bottom margin via JS layout reads.
    ## The values land at margin-bottom: -6.875px in one capture and
    ## -6.9375px in another, plus height: 20.89px vs 20.95px. Drop
    ## the inline styles on the wrapper, its viewport span, and
    ## anything tagged with the post-init js-fully-loaded marker.
    for el in soup.find_all(class_="code-select"):
        if el.get("style"):
            del el.attrs["style"]
    for el in soup.find_all(class_="js-fully-loaded"):
        if el.get("style"):
            del el.attrs["style"]
    ## .custom-scrollbar-container outer element AND every inner
    ## span/div with an inline style: the scrollbar widget reads
    ## getComputedStyle of its content area and writes the resulting
    ## height back as inline style, so the value flickers ~20px
    ## across captures depending on when font-metrics settled.
    for el in soup.find_all(class_="custom-scrollbar-container"):
        if el.get("style"):
            del el.attrs["style"]
        for inner in el.find_all(["span", "div"], style=True):
            del inner.attrs["style"]

    ## #mw-teleport-target moves between two locations in the DOM
    ## depending on which JS module installed it first. Same for the
    ## #ui-id-1 autocomplete placeholder. Drop them when empty.
    for el_id in ("mw-teleport-target", "ui-id-1"):
        el = soup.find(id=el_id)
        if el and not any(
            (isinstance(c, str) and c.strip()) or (hasattr(c, "name") and c.name)
            and c.get_text(strip=True)
            for c in el.contents
        ):
            el.decompose()
        elif el:
            ## Even when "non-empty" the contents are an empty overlay
            ## placeholder; drop the whole element since its position
            ## in the DOM races.
            text = el.get_text(strip=True)
            if not text:
                el.decompose()

    ## div.suggestions placeholder injected by mediawiki.searchSuggest
    ## once the search box is focused; both inner containers
    ## (.suggestions-results, .suggestions-special) start empty so
    ## the whole div renders nothing but its DOM presence races.
    for sg in soup.find_all(class_="suggestions"):
        if not sg.get_text(strip=True):
            sg.decompose()

    ## .CodeMirror-hscrollbar visibility flips between visible and
    ## hidden depending on whether the textarea content overflows
    ## horizontally at this exact moment; the rule depends on a
    ## resize observer that races networkidle. Drop the inline
    ## style entirely.
    for sb in soup.find_all(class_=re.compile(r"^CodeMirror-")):
        if sb.get("style"):
            del sb.attrs["style"]

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
        if tag.name == "input" and tag.get("name") in VOLATILE_INPUT_NAMES:
            tag["value"] = "SCRUBBED"
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

    ## Canonicalise incidental whitespace LAST, after every structural
    ## scrub above, so empty-<p> drops and text/comment collapsing see
    ## the final tree (and don't fight the volatile-content removals).
    _canonicalise_whitespace(soup)

    ## Within the size+depth cap enforced at the top of this function, so prettify's
    ## O(N*depth) indent cannot amplify here. The indented form is the same tree, identical
    ## on both sides of a diff of the same page.
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
            ## Only run the regex token-scrub on string values; a crafted
            ## non-string header value would crash pattern.sub with TypeError.
            if n == header_name and isinstance(v, str):
                v = pattern.sub(replacement, v)
        if n in URL_VALUED_HEADERS:
            v = _normalize_url(v)
        ## Host-scrub every header value: Onion-Location/Link/Location and
        ## friends carry the absolute wiki host, which would leak the true
        ## onion/hostname into the diff on a cross-wiki compare.
        if isinstance(v, str):
            v = _scrub_hosts(v)
        else:
            ## Fail CLOSED: a non-string header value (a list/dict from an untrusted
            ## received snapshot) could embed the host, so redact rather than pass the
            ## raw value through -- the same fail-closed posture as the rest of the scrub.
            v = "SCRUBBED"
        out[n] = v
    return dict(sorted(out.items()))


## URL substrings whose load is racy: only fetched when a particular
## piece of UI (icon, autocomplete dropdown, hover preview) reaches a
## ready state before networkidle fires. Dropping the manifest entry
## stops a present-vs-absent capture from looking like a regression.
RACY_LOAD_PATTERNS = (
    ## Font Awesome webfonts (fa-regular, fa-brands, fa-solid) are
    ## loaded on demand once an icon glyph renders; the icon trigger
    ## (auto-backup, brand chip, etc) is itself racy against
    ## networkidle, so whether the .woff2 makes it into the manifest
    ## varies between captures of the same wiki state.
    "/Font-Awesome_2023-08-03/webfonts/",
    ## TitleSuggest/oojs widget bundle: loaded when the user opens
    ## the search-title dropdown.
    "ext.MobileFrontend.styles",
    "mw-widget-titleWidget",
)

## MediaWiki ResourceLoader sometimes splits a module into its own
## request and sometimes bundles it with other modules. The bundled
## body has a different sha256 from the standalone body so the asset
## diff sees a NEW/GONE pair even though the same code runs. Drop
## standalone single-module load.php entries; the modules will still
## appear under another bundled URL elsewhere in the manifest.
_LOADPHP_MODULES_RE = re.compile(r"[?&]modules=([^&]+)")


def _is_single_module_loadphp(url: str) -> bool:
    if "load.php" not in url:
        return False
    m = _LOADPHP_MODULES_RE.search(url)
    if not m:
        return False
    modules = m.group(1)
    ## "%7C" is URL-encoded "|" -- single module if neither separator appears in
    ## the value. Percent-encoding is case-INsensitive (%7c == %7C), so upper-case
    ## the value before the compare or a lower-case "%7c" multi-module URL would
    ## misclassify as single and get the whole entry dropped.
    modules_upper = modules.upper()
    ## The ResourceLoader "startup" module is ALWAYS requested alone (modules=startup),
    ## so it looks like droppable single-module noise -- but unlike other single modules
    ## it never reappears bundled elsewhere, so dropping it strips startup.js from the
    ## manifest entirely AND makes the startup-body version scrub dead code (a real
    ## startup.js regression could never surface). Exempt it from the single-module drop.
    if modules_upper == "STARTUP":
        return False
    return "|" not in modules_upper and "%7C" not in modules_upper


def normalize_manifest(manifest: dict, page_url: str | None = None) -> dict:
    """Strip volatile query params, drop timing-flake entries, and
    normalise the headers dict per entry. Sort by URL for stable
    output.
    """
    out: dict[str, dict] = {}
    ## manifest.json is untrusted (a received cross-wiki snapshot). A crafted
    ## top-level scalar/list has no .items(); refuse rather than crash.
    if not isinstance(manifest, dict):
        print("normalize: manifest is not a JSON object; ignoring", file=sys.stderr)
        return {}
    for url, entry in manifest.items():
        ## A crafted entry that is not an object (string/number/list) would raise
        ## on the .get() calls below; skip it rather than abort the whole run.
        if not isinstance(entry, dict):
            print("normalize: skipping non-object manifest entry %r" % (url,), file=sys.stderr)
            continue
        if entry.get("status") == 404:
            continue
        ## 5xx entries: backend hiccup that snapshot.py's retry layer
        ## transparently recovered from. The retried 2xx body lives
        ## in the rendered DOM; the 5xx response entry is just noise
        ## that flickers across captures.
        status = entry.get("status")
        if isinstance(status, int) and 500 <= status < 600:
            continue
        ## body-unavailable entries: Playwright couldn't read the
        ## response body before the page closed (network race).
        ## Sometimes the SAME URL races on one capture but completes
        ## on the next, producing a status=None vs status=404 diff
        ## that's pure race noise. Drop both shapes.
        if entry.get("error") or status is None:
            continue
        ## Drop the page's OWN url (and its ?query / #fragment variants), NOT every url
        ## that merely shares its prefix: startswith(page_url) also erased an unrelated
        ## entry like .../wiki/API_documentation.css when page_url is .../wiki/A --
        ## silently dropping a legit manifest entry from the diff (a false negative in
        ## the exact regression-detection this tool exists for).
        if page_url and (url == page_url
                         or url.startswith(page_url + "?")
                         or url.startswith(page_url + "#")):
            continue
        ## XHR/api.php responses race the page load -- a tiny
        ## status-only body that finishes before networkidle shows
        ## up in one capture and after networkidle in another. Drop
        ## them; the page's observable state comes through the dom.html
        ## rather than the raw API blob.
        if "/w/api.php" in url:
            continue
        if any(p in url for p in RACY_LOAD_PATTERNS):
            continue
        if _is_single_module_loadphp(url):
            continue
        ## Host scrub the URL key too (no-op when DOM_DIFF_HOST_SCRUB is unset),
        ## so a cross-wiki diff matches by path instead of flagging every asset on
        ## the differing hostname.
        nurl = _scrub_hosts(_normalize_url(url))
        normalised_entry = dict(entry)
        ## Normalise headers when they are a dict; a crafted non-object "headers" would
        ## crash _normalize_headers' .items(). But dict(entry) has already COPIED the raw
        ## value through, so a non-dict headers (e.g. a list ["https://secret.onion/x"])
        ## would leak its host verbatim. Fail CLOSED: redact a present-but-non-dict headers
        ## so the no-host-leak guarantee holds for an untrusted snapshot whatever the shape.
        if isinstance(normalised_entry.get("headers"), dict):
            normalised_entry["headers"] = _normalize_headers(normalised_entry["headers"])
        elif "headers" in normalised_entry:
            normalised_entry["headers"] = "SCRUBBED"
        out.setdefault(nurl, normalised_entry)
    return dict(sorted(out.items()))


## MediaWiki's ResourceLoader "startup" module embeds a version hash
## for every module so the client knows whether its cached copy is
## current. The hashes rotate every server build even when no module
## content changed, so the startup.js body sha256 differs across
## captures of the same wiki state. We scrub the hash strings to
## SCRUBBED in-place; the rest of the file stays diffable.
##
## Hash strings appear in mw.loader.register() arguments as quoted
## short alphanumeric tokens like "1eggf" or "1um0c". The exact set:
##     mw.loader.register([
##         ["module.name", "1eggf"],
##         ...
##     ]);
##
## Catch any `"<2-8 lowercase alphanums>"` immediately following a
## known module-position marker.
STARTUP_VERSION_RE = re.compile(r'(?<=,)\s*"[a-z0-9]{2,8}"(?=[,\]])')


def _scrub_startup_module_body(body: str) -> str:
    return STARTUP_VERSION_RE.sub('"SCRUBBED"', body)


def _scrub_module_versions(body: str) -> str:
    """Scrub the "name@VERSION" tokens that appear in RL bundle bodies.
    Conservative: requires `"name@VERSION"` pattern with quotes so it
    won't false-positive on email addresses or similar."""
    return MODULE_VERSION_RE.sub(r"\1@SCRUBBED\2", body)


## Cookie names whose values rotate per session and aren't safe to
## diff. Matched case-insensitively as substrings.
SESSION_COOKIE_PATTERNS = ("session", "token", "csrf", "userid", "username")

## Cookie names whose PRESENCE itself is racy (set by a response that
## may or may not arrive before storage capture). Drop entirely so a
## present-vs-absent capture doesn't flip the diff. Matched
## case-insensitively as substrings.
DROP_COOKIE_PATTERNS = ("usedc", "geoip", "x-wikimedia-debug")

## localStorage / sessionStorage key patterns whose values rotate
## per session. The MediaWikiModuleStore key holds the ResourceLoader
## module cache (~MB of bundled JS keyed by per-build version hashes);
## present or absent depending on whether the browser flushed it before
## the snapshot fired. Drop the value -- the presence/absence of the
## key still surfaces, the cached content does not.
SESSION_STORAGE_KEY_PATTERNS = (
    re.compile(r"^mw-clientsession"),
    re.compile(r"^mw-rcfilters-saved-queries"),
    re.compile(r"^MediaWikiModuleStore:"),
    re.compile(r"^[a-f0-9]{16,}$"),
)

## localStorage keys to drop entirely (present-or-absent both map to
## absent). Use this for caches that are populated asynchronously by
## the browser and don't observably affect rendering.
DROP_STORAGE_KEY_PATTERNS = (
    re.compile(r"^MediaWikiModuleStore:"),
)


def _normalize_storage(storage: dict) -> dict:
    ## storage.json is untrusted (a received snapshot). A crafted non-object,
    ## or a non-list "cookies" / non-object cookie / non-string name, must be
    ## skipped rather than crash the .get()/.lower()/iteration below.
    if not isinstance(storage, dict):
        storage = {}
    cookies = []
    src_cookies = storage.get("cookies")
    for c in src_cookies if isinstance(src_cookies, list) else []:
        if not isinstance(c, dict):
            continue
        name = c.get("name", "")
        name_l = name.lower() if isinstance(name, str) else ""
        if any(p in name_l for p in DROP_COOKIE_PATTERNS):
            continue
        out = dict(c)
        ## Always scrub volatile timestamp / expires; cookie identity
        ## is (name, domain, path) -- value scrubbed when session-like.
        if any(p in name_l for p in SESSION_COOKIE_PATTERNS):
            out["value"] = "SCRUBBED"
        elif isinstance(out.get("value"), str):
            out["value"] = _scrub_hosts(out["value"])
        elif "value" in out:
            ## Fail CLOSED on a non-string cookie value (could embed the host).
            out["value"] = "SCRUBBED"
        ## Cookie identity is (name, domain, path); host-scrub the domain so
        ## the same cookie matches across a cross-wiki diff instead of the
        ## true host leaking through.
        if isinstance(out.get("domain"), str):
            out["domain"] = _scrub_hosts(out["domain"])
        elif "domain" in out:
            ## Fail CLOSED on a non-string cookie domain (could embed the host).
            out["domain"] = "SCRUBBED"
        for k in ("expires", "expirationDate"):
            if k in out:
                out[k] = "SCRUBBED"
        cookies.append(out)
    ## Coerce sort keys to str: a crafted non-string name/domain would otherwise
    ## make the mixed-type comparison raise.
    cookies.sort(key=lambda c: (str(c.get("name", "")), str(c.get("domain", ""))))

    def _scrub_kvs(kvs):
        out = {}
        ## A crafted non-object localStorage/sessionStorage would crash .items().
        for k, v in (kvs if isinstance(kvs, dict) else {}).items():
            if any(p.match(k) for p in DROP_STORAGE_KEY_PATTERNS):
                continue
            sc = any(p.match(k) for p in SESSION_STORAGE_KEY_PATTERNS)
            ## Fail CLOSED: a non-string storage value could embed the host, so redact
            ## it rather than pass the raw value through.
            out[k] = "SCRUBBED" if sc else (
                _scrub_hosts(v) if isinstance(v, str) else "SCRUBBED")
        return dict(sorted(out.items()))

    idb = storage.get("indexedDB_databases")
    return {
        "cookies": cookies,
        "localStorage": _scrub_kvs(storage.get("localStorage")),
        "sessionStorage": _scrub_kvs(storage.get("sessionStorage")),
        ## Coerce to str for a stable sort even if a crafted list mixes types.
        "indexedDB_databases": sorted(
            (str(x) for x in idb) if isinstance(idb, list) else []
        ),
    }


## Per-event scrubs applied to console message text before equality.
## Order matters: most specific first.
CONSOLE_TEXT_PATTERNS = (
    ## mwDev.tools.test.pageLoading prints per-event timestamps
    ## ("at HH:MM:SS.mmm") and per-event durations padded to align
    ## right at 5 chars ("    0 ms" / "  471 ms" / " 1234 ms"). The
    ## leading whitespace varies with the digit count, so consume it
    ## along with the number for a stable canonical form.
    (re.compile(r"\bat \d{2}:\d{2}:\d{2}\.\d{3}\b"), "at SCRUBBED"),
    (re.compile(r"\s*\d+ ms > "), "  N ms > "),
    ## MW often interpolates wgRequestId / wgUserId / wgPageId style
    ## values into console messages.
    (re.compile(r"\bwg[A-Za-z]+:[^\s,]+"), "wgFOO:SCRUBBED"),
    ## Long hex runs (session ids, content hashes).
    (re.compile(r"\b[0-9a-f]{16,}\b"), "HEX-SCRUBBED"),
)


## Whole-event drops applied before equality. Each pattern matches an
## entire console message; if any pattern matches, the event is
## dropped instead of normalised. Use for browser-emitted warnings
## whose PRESENCE is racy.
CONSOLE_DROP_PATTERNS = (
    ## "The resource ... was preloaded using link preload but not
    ## used within a few seconds from the window's load event."
    ## The browser fires this only if the preloaded asset (a font in
    ## the wiki's case) wasn't used in time, which races with the
    ## subresource scheduler.
    re.compile(r"preloaded using link preload but not used"),
    ## "Failed to load resource: the server responded with a status
    ## of 5xx ()". Backend hiccups under load that the snapshot.py
    ## retry layer transparently recovers from -- the console event
    ## for the failed attempt sticks around even after the retry
    ## succeeds, producing a present-vs-absent diff between captures.
    re.compile(r"Failed to load resource.*status of 5\d\d"),
)


def _normalize_console(events: list) -> list:
    """JS console: drop the per-page-id / per-session noise. Only the
    {type, text} pair matters for "did the new code introduce a new
    warning"; locations vary by build URL etc.
    """
    out = []
    seen = set()
    ## console.json is untrusted (a received snapshot). A crafted non-list, a
    ## non-object event, or a non-string text/type must be skipped/coerced rather
    ## than crash the iteration / .get() / regex ops below.
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        text = ev.get("text", "")
        if not isinstance(text, str):
            continue
        if any(p.search(text) for p in CONSOLE_DROP_PATTERNS):
            continue
        for pat, repl in CONSOLE_TEXT_PATTERNS:
            text = pat.sub(repl, text)
        ## Console messages interpolate absolute wiki URLs (load.php, api
        ## endpoints); host-scrub so the true host does not leak through
        ## console.json or errors.json's console_errors on a cross-wiki diff.
        text = _scrub_hosts(text)
        etype = ev.get("type", "")
        key = (etype if isinstance(etype, str) else "", text)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": key[0], "text": key[1]})
    out.sort(key=lambda e: (e["type"], e["text"]))
    return out


def _normalize_errors(errors: dict) -> dict:
    """Normalise the errors.json health channel.

    KEEPS 4xx -- that is the entire point: a missing favicon / broken asset
    must survive into the diff (manifest.json drops 4xx as asset-body noise).
    Drops 5xx (backend hiccups the snapshot retry layer recovered from) and
    racy on-demand loads, and scrubs volatile query params + hosts so the same
    404 matches across captures. Console errors run through the shared console
    normaliser, which drops the 5xx 'Failed to load resource' noise but keeps
    the 404 ones.
    """
    ## errors.json is untrusted (a received snapshot). A crafted non-object, a
    ## non-list http_errors/request_failures, a non-object item, or a non-string
    ## url/failure must be skipped/coerced rather than crash the .get()/iteration/
    ## `in`/regex ops below.
    if not isinstance(errors, dict):
        errors = {}

    def _clean(u):
        return _scrub_hosts(_normalize_url(u))

    def _as_list(key):
        v = errors.get(key)
        return v if isinstance(v, list) else []

    http = []
    seen = set()
    for e in _as_list("http_errors"):
        if not isinstance(e, dict):
            continue
        status = e.get("status")
        if isinstance(status, int) and 500 <= status < 600:
            continue
        raw = e.get("url", "")
        if not isinstance(raw, str):
            continue
        url = _clean(raw)
        if any(p in url for p in RACY_LOAD_PATTERNS):
            continue
        key = (status, url)
        if key in seen:
            continue
        seen.add(key)
        http.append({"status": status, "url": url})
    ## Coerce the status sort key to int: a crafted non-int status would otherwise
    ## make the mixed-type comparison raise.
    http.sort(key=lambda x: (x["status"] if isinstance(x["status"], int) else 0, x["url"]))

    fails = []
    seenf = set()
    for f in _as_list("request_failures"):
        if not isinstance(f, dict):
            continue
        raw = f.get("url", "")
        if not isinstance(raw, str):
            continue
        url = _clean(raw)
        if any(p in url for p in RACY_LOAD_PATTERNS):
            continue
        # failure is raw browser error text that embeds the request URL (e.g. Chromium
        # `net::ERR_FAILED at https://host/...`, CSP-blocked messages), so host-scrub it
        # like every other error-message surface -- the url scrub above does not reach it.
        raw_failure = f.get("failure", "")
        failure = _scrub_hosts(raw_failure) if isinstance(raw_failure, str) else ""
        key = (url, failure)
        if key in seenf:
            continue
        seenf.add(key)
        fails.append({"url": url, "failure": failure})
    fails.sort(key=lambda x: (x["url"], x["failure"]))

    return {
        "http_errors": http,
        "request_failures": fails,
        "console_errors": _normalize_console(errors.get("console_errors")),
    }


def _copy_json_scrubbed(src_path: Path, dst_path: Path) -> None:
    ## Otherwise-verbatim JSON copies (computed_styles, hover_styles,
    ## iframes_shadow) still embed absolute wiki URLs; host-scrub at the BYTE level
    ## when scrubbing is active so a non-UTF-8 body is neither U+FFFD-mangled nor
    ## crashes on a strict decode. A body with no host bytes stays bit-identical.
    ## No-op default (copy2).
    if HOST_SCRUB:
        data = src_path.read_bytes()
        scrubbed = _scrub_hosts_bytes(data)
        if scrubbed != data:
            dst_path.write_bytes(scrubbed)
            return
    shutil.copy2(src_path, dst_path)


def _copy_asset_bytes(src_a: Path, dst_assets: Path, sname: str, entry: dict) -> None:
    ## Byte path for an asset we do NOT text-rewrite: a genuine binary, or a
    ## text-labeled body that is not valid UTF-8 (content_type is UNTRUSTED) and so
    ## cannot be text-rewritten losslessly. Scrub the host at the BYTE level (fail
    ## closed for a mislabeled text body; a body with no host bytes stays
    ## bit-identical -- no lossy UTF-8 round-trip). Re-hash + update the manifest
    ## when the bytes changed, else copy through verbatim preserving the
    ## content-hash name.
    scrubbed = None
    if HOST_SCRUB:
        data = src_a.read_bytes()
        maybe = _scrub_hosts_bytes(data)
        if maybe != data:
            scrubbed = maybe
    if scrubbed is not None:
        digest = hashlib.sha256(scrubbed).hexdigest()
        new_name = digest + Path(sname).suffix
        (dst_assets / new_name).write_bytes(scrubbed)
        entry["asset"] = new_name
        entry["sha256"] = digest
        entry["size"] = len(scrubbed)
    else:
        target = dst_assets / sname
        if not target.exists():
            shutil.copy2(src_a, target)


def normalize_page_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)

    html = (src / "dom.html").read_text(encoding="utf-8")
    (dst / "dom.html").write_text(normalize_html(html), encoding="utf-8")

    ## Computed styles: bit-identical copy. The values come straight
    ## from getComputedStyle so they're already canonical for the
    ## viewport + scheme.
    cs_src = src / "computed_styles.json"
    if cs_src.exists():
        _copy_json_scrubbed(cs_src, dst / "computed_styles.json")

    ## Console events: scrub volatile bits and de-duplicate by
    ## (type, text) so two captures of the same wiki state emit the
    ## same canonical sequence.
    console_src = src / "console.json"
    if console_src.exists():
        try:
            events = json.loads(console_src.read_text(encoding="utf-8"))
        except Exception:
            events = []
        (dst / "console.json").write_text(
            json.dumps(_normalize_console(events), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    ## Storage: scrub session-like cookie values + hash-shaped
    ## localStorage/sessionStorage values.
    storage_src = src / "storage.json"
    if storage_src.exists():
        try:
            storage = json.loads(storage_src.read_text(encoding="utf-8"))
        except Exception:
            storage = {}
        (dst / "storage.json").write_text(
            json.dumps(_normalize_storage(storage), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    ## Errors (HTTP >= 400 / request failures / console errors): the health
    ## channel. Unlike manifest.json (which drops 4xx as asset-body noise),
    ## this KEEPS 4xx, so a missing favicon / broken asset surfaces in the diff.
    errors_src = src / "errors.json"
    if errors_src.exists():
        try:
            errs = json.loads(errors_src.read_text(encoding="utf-8"))
        except Exception:
            errs = {}
        (dst / "errors.json").write_text(
            json.dumps(_normalize_errors(errs), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    ## Hover styles + iframes/shadow: bit-identical copy. Their
    ## content is already deterministic for the wiki state -- no
    ## per-request volatility to scrub.
    for fn in ("hover_styles.json", "iframes_shadow.json"):
        p = src / fn
        if p.exists():
            _copy_json_scrubbed(p, dst / fn)

    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    ## manifest.json is untrusted (a received cross-wiki snapshot). A crafted
    ## top-level scalar/list has no .items(); treat it as empty rather than crash.
    if not isinstance(manifest, dict):
        print("normalize: manifest.json is not a JSON object; ignoring", file=sys.stderr)
        manifest = {}
    ## Infer the wiki page URL from the manifest. The first text/html
    ## 200 entry is by construction the navigation target.
    page_url = None
    for url, entry in manifest.items():
        ## Skip crafted non-object entries and non-string content_type before the
        ## .get()/.startswith() that would otherwise raise on them.
        if not isinstance(entry, dict):
            continue
        ct = entry.get("content_type", "")
        if (entry.get("status") == 200 and isinstance(ct, str)
                and ct.lower().startswith("text/html")):
            page_url = url
            break
    nm = normalize_manifest(manifest, page_url)

    ## Screenshot: copy as-is. Pixel-diff is the comparison step.
    screenshot_src = src / "screenshot.png"
    if screenshot_src.exists():
        shutil.copy2(screenshot_src, dst / "screenshot.png")

    ## Assets are content-hashed so already canonical; rsync-like
    ## mirror so the dst layout is self-contained. Exception: the
    ## ResourceLoader startup module's body carries per-build version
    ## hashes that rotate without content change -- scrub them in-place
    ## and refresh the manifest's sha256 to match.
    src_assets = src / "assets"
    dst_assets = dst / "assets"
    if src_assets.exists():
        dst_assets.mkdir(exist_ok=True)
        ## Track asset-bearing entries vs those skipped for a malformed SHAPE
        ## (wrong-type asset, or a caught per-entry error). If EVERY asset entry
        ## is malformed we must not emit a near-empty mirror as a clean pass --
        ## that false-green defeats the whole point of a faithful diff. See the
        ## fail-loud guard after the loop.
        asset_entries_total = 0
        asset_entries_failed = 0
        for url, entry in nm.items():
            if not isinstance(entry, dict) or "asset" not in entry:
                continue
            asset_entries_total += 1
            ## entry["asset"] comes from manifest.json, which for a RECEIVED cross-wiki
            ## snapshot (this tool diffs snapshots across hosts/CI) is untrusted input.
            ## A crafted asset that is null / a number / a list would crash `src_assets
            ## / sname`; treat a non-string asset as a malformed entry (shape error).
            sname = entry.get("asset")
            if not isinstance(sname, str):
                print(
                    "normalize: skipping entry %r: asset is not a string: %r"
                    % (url, sname),
                    file=sys.stderr,
                )
                asset_entries_failed += 1
                continue
            ## A legitimate asset name is FLAT (<sha256>.<ext>, per the module
            ## docstring); a path separator means an escaping value (../x, /abs ->
            ## arbitrary-file read) OR a nested one (sub/x -> the plain-copy branch's
            ## dst/assets/sub is never mkdir'd -> FileNotFoundError crash). Refuse any
            ## non-flat name. A refused entry copies NOTHING, so -- like a shape error or
            ## a missing source -- it DOES count toward the all-dropped fail-loud tally: a
            ## manifest whose entries are ALL refused yields the same near-empty mirror and
            ## must not exit 0 as a clean pass.
            if sname in ("", ".", "..") or "/" in sname or "\\" in sname:
                print("normalize: refusing non-flat asset name %r" % sname, file=sys.stderr)
                asset_entries_failed += 1
                continue
            ## Per-entry isolation: one malformed asset entry must not abort the whole
            ## normalize of an untrusted artifact. Catch only input-shape / filesystem
            ## classes (TypeError/KeyError/ValueError/OSError) -- NOT a blanket Exception
            ## (nor AttributeError, which the isinstance guards above already preclude),
            ## so a genuine logic bug in the copy/scrub path still surfaces loudly.
            try:
                src_a = src_assets / sname
                ## Belt-and-braces: a flat name that is a symlink inside assets/ could
                ## still resolve outside it, so keep the containment check.
                if not src_a.resolve().is_relative_to(src_assets.resolve()):
                    print("normalize: refusing out-of-tree asset %r" % sname, file=sys.stderr)
                    asset_entries_failed += 1
                    continue
                ## A missing source body also copies nothing -> counts toward the tally,
                ## so an all-missing-source manifest fails loud rather than mirror empty.
                if not src_a.exists():
                    asset_entries_failed += 1
                    continue
                ct = entry.get("content_type", "")
                ## A crafted non-string content_type would crash .startswith below.
                if not isinstance(ct, str):
                    ct = ""
                ## Media types are case-INSENSITIVE (RFC 7231), so a "Application/Javascript"
                ## variant must still select the scrub -- else the version-hash flake-kill
                ## silently no-ops. Lowercase before every startswith check below.
                ct = ct.lower()
                ## Three categories of asset get in-place text rewrites; everything
                ## else copies through at the byte level (see _copy_asset_bytes).
                ## content_type is UNTRUSTED, so decide the rewrite mode first, then
                ## decode STRICTLY below -- a body that is not valid UTF-8 cannot be
                ## text-rewritten losslessly.
                if "modules=startup" in url and ct.startswith(
                    ("application/javascript", "text/javascript")
                ):
                    rewrite = "startup"
                elif "load.php" in url and ct.startswith(
                    ("application/javascript", "text/javascript")
                ):
                    rewrite = "loadphp"
                elif ct.startswith("text/html"):
                    rewrite = "html"
                elif HOST_SCRUB and _is_text_asset(ct):
                    ## Cross-wiki host scrub: CSS/JS/SVG bodies embed absolute URLs to
                    ## the wiki host, which would otherwise differ on every old-vs-www
                    ## diff. Only read+rewrite when scrubbing is actually active.
                    rewrite = "scrub"
                else:
                    ## content_type does NOT prove this a text asset (or it is a
                    ## non-scrub binary): copy through at the byte level.
                    _copy_asset_bytes(src_a, dst_assets, sname, entry)
                    continue
                ## Strict decode: never errors="replace"-mangle an adversarial or a
                ## legit non-UTF-8 body into the canonical output -- that U+FFFD churn
                ## would break the bit-identical invariant. On decode failure, route the
                ## body through the SAME byte path as a binary: byte-copied and
                ## host-scrubbed at the byte level, NOT dropped (an asset that copies a
                ## body is not a "failed" entry).
                try:
                    body = src_a.read_bytes().decode("utf-8")
                except UnicodeDecodeError:
                    _copy_asset_bytes(src_a, dst_assets, sname, entry)
                    continue
                if rewrite == "startup":
                    body = _scrub_startup_module_body(body)
                    body = _scrub_module_versions(body)
                elif rewrite == "loadphp":
                    ## RL bundles other than startup also carry the
                    ## "name@VERSION" tokens; same per-build noise.
                    body = _scrub_module_versions(body)
                elif rewrite == "html":
                    ## HTML asset bodies (e.g. pages loaded as embeds during
                    ## navigation) carry the same per-request wgRequestId /
                    ## wgBackendResponseTime / mw.user.options.set noise as
                    ## dom.html. Run them through the same normaliser.
                    body = normalize_html(body)
                ## Cross-wiki host scrub of the body. No-op when DOM_DIFF_HOST_SCRUB is
                ## unset; idempotent for the text/html branch (already scrubbed via
                ## normalize_html). This is the "(and asset/style text)" the HOST_SCRUB
                ## note above promises.
                body = _scrub_hosts(body)
                ## Re-hash so the manifest sha256 matches the rewritten body.
                digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
                new_name = digest + Path(sname).suffix
                (dst_assets / new_name).write_text(body, encoding="utf-8")
                entry["asset"] = new_name
                entry["sha256"] = digest
                entry["size"] = len(body.encode("utf-8"))
            except (TypeError, KeyError, ValueError, OSError) as exc:
                print(
                    "normalize: skipping asset entry %r: %r" % (url, exc),
                    file=sys.stderr,
                )
                asset_entries_failed += 1
                continue
        ## Fail-loud on the systematic-malformation case: if the manifest HAD asset
        ## entries but every single one was malformed, normalize would otherwise
        ## finish 0 with an empty assets/ mirror -- a lie that reads as a clean diff.
        ## All-skipped is the clear, defensible threshold; a single bad entry among
        ## good ones is still tolerated.
        if asset_entries_total and asset_entries_failed == asset_entries_total:
            raise SystemExit(
                "normalize: all %d asset entries were malformed; refusing to emit a "
                "near-empty mirror as success" % asset_entries_total
            )

    (dst / "manifest.json").write_text(
        json.dumps(nm, indent=2, sort_keys=True), encoding="utf-8"
    )


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
