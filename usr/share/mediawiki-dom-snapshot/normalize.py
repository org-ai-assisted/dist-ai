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


def _under_whitespace_sensitive(node) -> bool:
    for parent in node.parents:
        if getattr(parent, "name", None) in WHITESPACE_SENSITIVE_TAGS:
            return True
    return False


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
    for t in list(soup.find_all(string=True)):
        if isinstance(t, Comment):
            continue
        if _under_whitespace_sensitive(t):
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
    ## mw.user.options.set({...}); gets populated by MediaWiki after the
    ## first user-mode visit and persists; subsequent captures see
    ## entries the first capture wrote (rcfilters-limit, rcfilters-
    ## saved-queries, ...) -- and a capture against a freshly-created
    ## user has the call ABSENT entirely while a later capture has it
    ## PRESENT. Drop the entire statement (including the trailing
    ## semicolon) so present-or-absent stops mattering.
    text = re.sub(
        r"mw\.user\.options\.set\(\{.+?\}\);?",
        "",
        text,
        flags=re.DOTALL,
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
## on the raw HTML (and asset/style text) so only real content deltas survive.
## Empty (the default) is a no-op, so same-host diffs are unaffected.
HOST_SCRUB = tuple(
    h.strip() for h in os.environ.get("DOM_DIFF_HOST_SCRUB", "").split(",") if h.strip()
)
HOST_SCRUB_PLACEHOLDER = "wiki-host.invalid"


def _scrub_hosts(text: str) -> str:
    for host in HOST_SCRUB:
        text = text.replace(host, HOST_SCRUB_PLACEHOLDER)
    return text


def _is_text_asset(content_type: str) -> bool:
    ## Text-shaped asset bodies (CSS, JS, SVG) can embed absolute URLs to the wiki
    ## host; binary assets (images, fonts) cannot, so they copy through untouched.
    return content_type.startswith(("text/", "application/javascript")) or "svg" in content_type


def normalize_html(html: str) -> str:
    html = _scrub_hosts(html)
    ## Scrub JS-generated random ids early so the BeautifulSoup parse
    ## sees the canonical form. Safer to do this on the string than
    ## inside the tree walk since the ids appear both as attribute
    ## values AND inside href fragments and inline script bodies.
    for pat, repl in RANDOM_ID_PATTERNS:
        html = pat.sub(repl, html)

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
    ## "%7C" is URL-encoded "|" -- single module if neither separator
    ## appears in the value.
    return "|" not in modules and "%7C" not in modules


def normalize_manifest(manifest: dict, page_url: str | None = None) -> dict:
    """Strip volatile query params, drop timing-flake entries, and
    normalise the headers dict per entry. Sort by URL for stable
    output.
    """
    out: dict[str, dict] = {}
    for url, entry in manifest.items():
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
        if page_url and url.startswith(page_url):
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
        if "headers" in normalised_entry:
            normalised_entry["headers"] = _normalize_headers(normalised_entry["headers"])
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
    cookies = []
    for c in (storage.get("cookies") or []):
        name = c.get("name", "")
        name_l = name.lower()
        if any(p in name_l for p in DROP_COOKIE_PATTERNS):
            continue
        out = dict(c)
        ## Always scrub volatile timestamp / expires; cookie identity
        ## is (name, domain, path) -- value scrubbed when session-like.
        if any(p in name_l for p in SESSION_COOKIE_PATTERNS):
            out["value"] = "SCRUBBED"
        for k in ("expires", "expirationDate"):
            if k in out:
                out[k] = "SCRUBBED"
        cookies.append(out)
    cookies.sort(key=lambda c: (c.get("name", ""), c.get("domain", "")))

    def _scrub_kvs(kvs):
        out = {}
        for k, v in (kvs or {}).items():
            if any(p.match(k) for p in DROP_STORAGE_KEY_PATTERNS):
                continue
            sc = any(p.match(k) for p in SESSION_STORAGE_KEY_PATTERNS)
            out[k] = "SCRUBBED" if sc else v
        return dict(sorted(out.items()))

    return {
        "cookies": cookies,
        "localStorage": _scrub_kvs(storage.get("localStorage")),
        "sessionStorage": _scrub_kvs(storage.get("sessionStorage")),
        "indexedDB_databases": sorted(storage.get("indexedDB_databases") or []),
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
    for ev in events or []:
        text = ev.get("text", "")
        if any(p.search(text) for p in CONSOLE_DROP_PATTERNS):
            continue
        for pat, repl in CONSOLE_TEXT_PATTERNS:
            text = pat.sub(repl, text)
        key = (ev.get("type", ""), text)
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
    def _clean(u):
        return _scrub_hosts(_normalize_url(u))

    http = []
    seen = set()
    for e in errors.get("http_errors") or []:
        status = e.get("status")
        if isinstance(status, int) and 500 <= status < 600:
            continue
        url = _clean(e.get("url", ""))
        if any(p in url for p in RACY_LOAD_PATTERNS):
            continue
        key = (status, url)
        if key in seen:
            continue
        seen.add(key)
        http.append({"status": status, "url": url})
    http.sort(key=lambda x: (x.get("status") or 0, x["url"]))

    fails = []
    seenf = set()
    for f in errors.get("request_failures") or []:
        url = _clean(f.get("url", ""))
        if any(p in url for p in RACY_LOAD_PATTERNS):
            continue
        failure = f.get("failure", "")
        key = (url, failure)
        if key in seenf:
            continue
        seenf.add(key)
        fails.append({"url": url, "failure": failure})
    fails.sort(key=lambda x: (x["url"], x["failure"]))

    return {
        "http_errors": http,
        "request_failures": fails,
        "console_errors": _normalize_console(errors.get("console_errors") or []),
    }


def normalize_page_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)

    html = (src / "dom.html").read_text(encoding="utf-8")
    (dst / "dom.html").write_text(normalize_html(html), encoding="utf-8")

    ## Computed styles: bit-identical copy. The values come straight
    ## from getComputedStyle so they're already canonical for the
    ## viewport + scheme.
    cs_src = src / "computed_styles.json"
    if cs_src.exists():
        shutil.copy2(cs_src, dst / "computed_styles.json")

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
            shutil.copy2(p, dst / fn)

    manifest = json.loads((src / "manifest.json").read_text(encoding="utf-8"))
    ## Infer the wiki page URL from the manifest. The first text/html
    ## 200 entry is by construction the navigation target.
    page_url = None
    for url, entry in manifest.items():
        if entry.get("status") == 200 and entry.get("content_type", "").startswith("text/html"):
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
        for url, entry in nm.items():
            if "asset" not in entry:
                continue
            sname = entry["asset"]
            src_a = src_assets / sname
            if not src_a.exists():
                continue
            ct = entry.get("content_type", "")
            ## Three categories of asset get in-place rewrites; everything
            ## else copies through untouched.
            if "modules=startup" in url and ct.startswith(
                ("application/javascript", "text/javascript")
            ):
                body = src_a.read_text(encoding="utf-8", errors="replace")
                body = _scrub_startup_module_body(body)
                body = _scrub_module_versions(body)
            elif "load.php" in url and ct.startswith(
                ("application/javascript", "text/javascript")
            ):
                ## RL bundles other than startup also carry the
                ## "name@VERSION" tokens; same per-build noise.
                body = src_a.read_text(encoding="utf-8", errors="replace")
                body = _scrub_module_versions(body)
            elif ct.startswith("text/html"):
                ## HTML asset bodies (e.g. pages loaded as embeds during
                ## navigation) carry the same per-request wgRequestId /
                ## wgBackendResponseTime / mw.user.options.set noise as
                ## dom.html. Run them through the same normaliser.
                body = src_a.read_text(encoding="utf-8", errors="replace")
                body = normalize_html(body)
            elif HOST_SCRUB and _is_text_asset(ct):
                ## Cross-wiki host scrub: CSS/JS/SVG bodies embed absolute URLs to
                ## the wiki host, which would otherwise differ on every old-vs-www
                ## diff. Only read+rewrite when scrubbing is actually active.
                body = src_a.read_text(encoding="utf-8", errors="replace")
            else:
                target = dst_assets / sname
                if not target.exists():
                    shutil.copy2(src_a, target)
                continue
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
