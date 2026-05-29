#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Drive headless Chromium against a MediaWiki and dump a complete
regression-test corpus per page-and-mode.

A "mode" is a 4-tuple of (auth, visit, viewport, color_scheme):
    auth          anon | user
    visit         first | repeat
    viewport      desktop (1280x800) | mobile (390x844)
    color_scheme  light | dark

Default is all 16 combinations. CAPTURE_MODES limits the set.

Per (page, mode) capture writes:

    RAW_DIR/<page>/<mode>/
        dom.html              post-JS rendered HTML
        screenshot.png        viewport screenshot (deterministic)
        manifest.json         URL -> {sha256, size, status, content_type, headers}
        assets/<sha256>.<ext> raw asset body, indexed by content hash
        console.json          [{type, text, location}] -- JS console
                              messages + pageerror events
        computed_styles.json  {selector: {prop: value, ...}, ...}
                              for a curated set of structural elements

Env:
  BASE_URL        target wiki origin                default https://www.kicksecure.com
  RAW_DIR         destination root                  default /var/lib/mediawiki-dom-snapshot/raw
  PAGES_FILE      one title per line                default /etc/mediawiki-dom-snapshot/pages.conf
  TIMEOUT_MS      per-page timeout, milliseconds    default 30000
  CONCURRENCY     parallel captures                 default 4
  CAPTURE_MODES   comma-separated subset, or "all"  default all
  WIKI_USER       username for auth=user modes      default (unset, user modes skipped)
  WIKI_PASSWORD   password for auth=user modes
"""
import asyncio
import hashlib
import json
import mimetypes
import os
import sys
from pathlib import Path
from playwright.async_api import async_playwright

BASE = os.environ.get("BASE_URL", "https://www.kicksecure.com").rstrip("/")
RAW_DIR = Path(os.environ.get("RAW_DIR", "/var/lib/mediawiki-dom-snapshot/raw"))
PAGES_FILE = Path(os.environ.get("PAGES_FILE", "/etc/mediawiki-dom-snapshot/pages.conf"))
TIMEOUT_MS = int(os.environ.get("TIMEOUT_MS", "30000"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "4"))

WIKI_USER = os.environ.get("WIKI_USER", "")
WIKI_PASSWORD = os.environ.get("WIKI_PASSWORD", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

## Comma-separated wiki page titles eligible for the postedit intent.
## The intent edits the page (appends a hidden marker line), captures
## the rendered result, then reverts. Pages should be safe to mutate
## under test (low traffic, no live readers); operators add a private
## TestpageEditPostEdit-style page to their wiki and list it here.
## Empty default = postedit intent silently skips every page.
POSTEDIT_PAGES = {
    p.strip() for p in os.environ.get("POSTEDIT_PAGES", "").split(",") if p.strip()
}

VIEWPORTS = {
    "desktop": (1280, 800),
    "mobile": (390, 844),
}

## Build the mode list.
##
## Mode tuple: (label, auth, visit, vp, scheme, intent, browser, locale)
##
##   auth     anon | user | admin   (admin only if ADMIN_USER set)
##   visit    first | repeat
##   vp       desktop | mobile
##   scheme   light | dark | print   (print emulates print stylesheet)
##   intent   view | edit | search | postedit | hover
##              view      -- standard read-only page view (default)
##              edit      -- action=edit form, user/admin modes only
##              search    -- type a search query, capture results
##              postedit  -- edit the page, save, capture rendered
##                           result, then revert; user/admin only;
##                           only runs against pages whose title
##                           starts with "TestpageEditPostEdit"
##              hover     -- view + hover/focus over each link/button
##                           in a curated selector list; captures
##                           per-selector computed-style snapshots
##                           into hover_styles.json
##   browser  chromium | firefox | webkit  (default chromium only)
##   locale   en | <BCP47>  (Accept-Language; default "en" only)
##
## Cross-dim pruning to keep the mode count tractable:
##   - edit/postedit require auth != anon
##   - edit/search/postedit/hover only generated for the canonical
##     desktop-light viewport+scheme
##   - locale != en only generated for canonical
##     anon-first-desktop-light-view-chromium combination
##   - dark + print only on view intent
ALL_BROWSERS = ["chromium", "firefox", "webkit"]
DEFAULT_LOCALE = "en"


def _parse_browsers() -> list[str]:
    raw = os.environ.get("BROWSERS", "chromium").strip()
    if raw == "all":
        return list(ALL_BROWSERS)
    out = [b.strip() for b in raw.split(",") if b.strip()]
    for b in out:
        if b not in ALL_BROWSERS:
            raise SystemExit(f"snapshot: unknown BROWSERS entry: {b}")
    return out


def _parse_locales() -> list[str]:
    raw = os.environ.get("LOCALES", DEFAULT_LOCALE).strip()
    return [loc.strip() for loc in raw.split(",") if loc.strip()]


def _parse_auths() -> list[str]:
    """anon and user always candidates; admin only if creds provided."""
    out = ["anon"]
    if WIKI_USER and WIKI_PASSWORD:
        out.append("user")
    if ADMIN_USER and ADMIN_PASSWORD:
        out.append("admin")
    return out


def _all_modes() -> list[tuple]:
    browsers = _parse_browsers()
    locales = _parse_locales()
    auths = _parse_auths()
    out = []
    for auth in auths:
        for visit in ("first", "repeat"):
            for vp in ("desktop", "mobile"):
                for scheme in ("light", "dark", "print"):
                    for intent in ("view", "edit", "search", "postedit", "hover"):
                        if intent in ("edit", "postedit") and auth == "anon":
                            continue
                        if intent in ("edit", "search", "postedit", "hover"):
                            if vp != "desktop" or scheme != "light":
                                continue
                        for browser in browsers:
                            for locale in locales:
                                ## Locale != en only matters for the
                                ## canonical anon-first-desktop-light-
                                ## view-chromium combination.
                                if locale != DEFAULT_LOCALE:
                                    if not (
                                        auth == "anon"
                                        and visit == "first"
                                        and vp == "desktop"
                                        and scheme == "light"
                                        and intent == "view"
                                        and browser == "chromium"
                                    ):
                                        continue
                                label_parts = [
                                    auth, visit, vp, scheme, intent, browser,
                                ]
                                if locale != DEFAULT_LOCALE:
                                    label_parts.append(f"locale-{locale}")
                                label = "-".join(label_parts)
                                out.append((
                                    label, auth, visit, vp, scheme,
                                    intent, browser, locale,
                                ))
    return out


ALL_MODES = _all_modes()
ALL_MODE_LABELS = [m[0] for m in ALL_MODES]


def parse_modes() -> list[tuple]:
    raw = os.environ.get("CAPTURE_MODES", "all").strip()
    if raw == "all":
        wanted = ALL_MODE_LABELS
    else:
        wanted = [m.strip() for m in raw.split(",") if m.strip()]
        for m in wanted:
            if m not in ALL_MODE_LABELS:
                raise SystemExit(f"snapshot: unknown CAPTURE_MODES entry: {m}")
    modes = [m for m in ALL_MODES if m[0] in wanted]
    if any(m[1] == "user" for m in modes) and not (WIKI_USER and WIKI_PASSWORD):
        print(
            "snapshot: WIKI_USER/WIKI_PASSWORD unset; auth=user modes will be skipped",
            file=sys.stderr,
        )
        modes = [m for m in modes if m[1] != "user"]
    if any(m[1] == "admin" for m in modes) and not (ADMIN_USER and ADMIN_PASSWORD):
        print(
            "snapshot: ADMIN_USER/ADMIN_PASSWORD unset; auth=admin modes will be skipped",
            file=sys.stderr,
        )
        modes = [m for m in modes if m[1] != "admin"]
    return modes


def load_pages() -> list[str]:
    out = []
    for line in PAGES_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def safe_name(title: str) -> str:
    return title.replace(":", "_").replace("/", "_").replace(" ", "_")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ext_for(content_type: str, url: str) -> str:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    EXACT = {
        "text/html": ".html",
        "text/css": ".css",
        "application/javascript": ".js",
        "text/javascript": ".js",
        "application/json": ".json",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/svg+xml": ".svg",
        "image/webp": ".webp",
        "image/gif": ".gif",
        "image/x-icon": ".ico",
        "font/woff": ".woff",
        "font/woff2": ".woff2",
        "application/font-woff": ".woff",
        "application/font-woff2": ".woff2",
        "application/x-font-woff": ".woff",
        "text/plain": ".txt",
    }
    if ct in EXACT:
        return EXACT[ct]
    guess = mimetypes.guess_extension(ct) if ct else None
    if guess:
        return guess
    suffix = Path(url.split("?", 1)[0]).suffix.lower()
    if suffix and len(suffix) <= 6:
        return suffix
    return ".bin"


async def login(context, base_url: str, username: str, password: str) -> bool:
    """MediaWiki action=login flow; injects session cookies into context."""
    api = f"{base_url}/w/api.php"
    sess = await context.request.get(
        api, params={"action": "query", "meta": "tokens", "type": "login", "format": "json"}
    )
    try:
        body = await sess.json()
        login_token = body["query"]["tokens"]["logintoken"]
    except Exception as exc:
        print(f"snapshot: login token fetch failed: {exc}", file=sys.stderr)
        return False
    resp = await context.request.post(
        api,
        form={
            "action": "login",
            "lgname": username,
            "lgpassword": password,
            "lgtoken": login_token,
            "format": "json",
        },
    )
    try:
        body = await resp.json()
        result = body.get("login", {}).get("result", "")
    except Exception as exc:
        print(f"snapshot: login POST failed to parse: {exc}", file=sys.stderr)
        return False
    if result != "Success":
        print(f"snapshot: login failed: {body}", file=sys.stderr)
        return False
    return True


def record_response_factory(page_dir: Path, manifest: dict):
    assets_dir = page_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    async def on_response(response):
        url = response.url
        if url in manifest:
            return
        try:
            body = await response.body()
        except Exception as exc:
            manifest[url] = {"error": f"body unavailable: {exc}"}
            return
        digest = sha256_hex(body)
        headers = {k.lower(): v for k, v in response.headers.items()}
        ct = headers.get("content-type", "")
        ext = ext_for(ct, url)
        asset_path = assets_dir / f"{digest}{ext}"
        if not asset_path.exists():
            asset_path.write_bytes(body)
        manifest[url] = {
            "sha256": digest,
            "size": len(body),
            "content_type": ct,
            "status": response.status,
            "asset": asset_path.name,
            "headers": headers,
        }

    return on_response


## Curated structural selectors for computed-style snapshots. CSS
## regressions invisible to the HTML diff (specificity changes, cascade
## order changes, !important toggles) surface here.
COMPUTED_STYLE_SELECTORS = [
    "body", "html", "main", "#mw-content-text",
    "h1", "h2", "h3", ".first-heading", "#firstHeading",
    "#siteNotice", ".sitenotice-banner", "#fly-in-notification-panel",
    "header", "footer", "#mw-footer",
    "a", ".mw-body-content a", "code", "pre",
    ".wikitable", "table.wikitable th", "table.wikitable td",
    ".info-box", ".intro-like",
    "#back-to-top-button", ".close-panel",
    ".kicksecure-hide-all-banners",
]

## CSS properties to record per element. Snapshotting *every* property
## would be ~250 lines per element; this list covers the ones whose
## change surfaces a real regression.
COMPUTED_STYLE_PROPS = [
    "display", "position", "top", "right", "bottom", "left",
    "width", "height", "min-width", "min-height", "max-width", "max-height",
    "margin", "padding", "border",
    "color", "background-color", "background-image",
    "font-family", "font-size", "font-weight", "line-height",
    "text-align", "text-decoration",
    "opacity", "visibility", "z-index",
    "transform", "transition",
    "border-radius", "box-shadow",
    "overflow", "white-space",
]


## Marker line appended by the postedit flow. Deterministic so the
## diff against a pre-edit baseline shows a single 1-line delta when
## the save round-trip works.
POSTEDIT_MARKER = "<!-- mediawiki-dom-snapshot postedit marker DO NOT REMOVE -->"


async def _api_edit(context, base_url: str, title: str, append_marker: bool) -> bool:
    """Append (or remove) the postedit marker line via the MW write API.
    Uses csrf token issued by action=query&meta=tokens.
    """
    api = f"{base_url}/w/api.php"
    tokens_resp = await context.request.get(
        api, params={"action": "query", "meta": "tokens", "format": "json"}
    )
    try:
        csrf = (await tokens_resp.json())["query"]["tokens"]["csrftoken"]
    except Exception as exc:
        print(f"snapshot: csrf token fetch failed: {exc}", file=sys.stderr)
        return False
    ## Fetch current wikitext.
    rev_resp = await context.request.get(
        api,
        params={
            "action": "query", "prop": "revisions", "rvprop": "content",
            "rvslots": "main", "titles": title, "format": "json",
        },
    )
    try:
        pages = (await rev_resp.json())["query"]["pages"]
        page_id = next(iter(pages))
        slots = pages[page_id]["revisions"][0]["slots"]["main"]
        current = slots.get("*", slots.get("content", ""))
    except Exception:
        current = ""  ## page might not exist yet
    if append_marker:
        new_text = current.rstrip() + "\n" + POSTEDIT_MARKER + "\n"
    else:
        new_text = current.replace("\n" + POSTEDIT_MARKER + "\n", "").rstrip()
    edit_resp = await context.request.post(
        api,
        form={
            "action": "edit", "title": title, "text": new_text,
            "token": csrf, "format": "json", "bot": "1",
            "summary": "mediawiki-dom-snapshot test edit",
        },
    )
    try:
        result = (await edit_resp.json()).get("edit", {}).get("result", "")
    except Exception as exc:
        print(f"snapshot: edit POST failed: {exc}", file=sys.stderr)
        return False
    return result == "Success"


async def capture_storage(page, context) -> dict:
    """Snapshot every form of browser-side state the page can write to:
    localStorage, sessionStorage, document cookies (including HttpOnly
    via Playwright's context.cookies()), and the list of IndexedDB
    database names. The Set of databases matters even when their
    content is opaque.
    """
    storage = await page.evaluate("""
        () => {
            const ls = {};
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                ls[k] = localStorage.getItem(k);
            }
            const ss = {};
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                ss[k] = sessionStorage.getItem(k);
            }
            return {localStorage: ls, sessionStorage: ss};
        }
    """)
    try:
        idb = await page.evaluate(
            "() => (indexedDB.databases ? indexedDB.databases().then(dbs => dbs.map(d => d.name)) : [])"
        )
    except Exception:
        idb = []
    cookies = await context.cookies()
    return {
        "localStorage": storage.get("localStorage", {}),
        "sessionStorage": storage.get("sessionStorage", {}),
        "cookies": cookies,
        "indexedDB_databases": idb,
    }


## Curated selectors used for the hover/focus state capture. Each
## resolves to ONE element; we hover and focus that element and
## snapshot its computed-style so theme changes / hover overlays
## become diff-visible. Selectors are picked so they're stable across
## pages (main nav, sidebar, search box, etc.).
HOVER_SELECTORS = [
    "#searchInput",
    "#searchButton",
    "#n-mainpage-description a",
    ".mw-portlet a",
    "#firstHeading",
    "#mw-content-text a",
    ".vector-menu-content-list a",
    "#footer a",
    "#fly-in-notification-panel a",
    ".close-panel",
    "#back-to-top-button",
]


async def capture_one(browser, mode_tuple, title: str) -> tuple[str, str, int, int]:
    label, auth, visit, vp_name, scheme, intent, browser_name, locale = mode_tuple

    ## postedit only runs on pages explicitly listed in POSTEDIT_PAGES.
    if intent == "postedit" and title not in POSTEDIT_PAGES:
        return (label, title, 0, 0)  ## silently skip; caller treats 0 as no-op
    page_dir = RAW_DIR / safe_name(title) / label
    page_dir.mkdir(parents=True, exist_ok=True)
    W, H = VIEWPORTS[vp_name]

    ## Playwright's color_scheme accepts light, dark, no-preference.
    ## "print" isn't a context option -- we emulate_media after page
    ## creation instead.
    ctx_scheme = scheme if scheme in ("light", "dark") else "light"
    ctx_kwargs = dict(
        viewport={"width": W, "height": H},
        ignore_https_errors=True,
        color_scheme=ctx_scheme,
        locale=locale or DEFAULT_LOCALE,
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 "
            "mediawiki-dom-snapshot/0.4"
        ),
    )
    if locale and locale != DEFAULT_LOCALE:
        ctx_kwargs["extra_http_headers"] = {"Accept-Language": locale}
    context = await browser.new_context(**ctx_kwargs)

    if auth in ("user", "admin"):
        user = WIKI_USER if auth == "user" else ADMIN_USER
        pw = WIKI_PASSWORD if auth == "user" else ADMIN_PASSWORD
        if not await login(context, BASE, user, pw):
            await context.close()
            raise RuntimeError(f"login failed for mode {label}")

    page = await context.new_page()
    if scheme == "print":
        await page.emulate_media(media="print")
    manifest: dict[str, dict] = {}
    page.on("response", lambda r: asyncio.create_task(
        record_response_factory(page_dir, manifest)(r)
    ))

    console_events: list[dict] = []

    def _on_console(msg):
        ## msg.location is a dict {url, lineNumber, columnNumber}.
        try:
            loc = msg.location
        except Exception:
            loc = {}
        console_events.append({
            "type": msg.type,
            "text": msg.text,
            "url": loc.get("url") if isinstance(loc, dict) else "",
        })

    def _on_pageerror(exc):
        console_events.append({"type": "pageerror", "text": str(exc), "url": ""})

    page.on("console", _on_console)
    page.on("pageerror", _on_pageerror)

    safe = title.replace(" ", "_")
    api = f"{BASE}/w/api.php"

    ## Build the navigation URL for this intent.
    if intent == "edit":
        url = f"{BASE}/w/index.php?title={safe}&action=edit"
    elif intent == "search":
        ## Special:Search with the page title as query; lets us also
        ## exercise the search-results rendering path.
        url = f"{BASE}/wiki/Special:Search?search={safe}"
    elif intent == "postedit":
        ## For postedit we do an edit + save cycle first, then render
        ## the page in view mode and capture that. The cycle uses the
        ## MW write API, not the form, so it's deterministic.
        url = f"{BASE}/wiki/{safe}"
    else:
        url = f"{BASE}/wiki/{safe}"

    try:
        try:
            await page.request.post(
                api,
                form={"action": "purge", "format": "json", "titles": safe},
                timeout=TIMEOUT_MS,
            )
        except Exception:
            pass

        ## postedit flow: edit the page via the MW API, then load it.
        if intent == "postedit":
            await _api_edit(context, BASE, safe, append_marker=True)

        n_visits = 2 if visit == "repeat" else 1
        for _ in range(n_visits):
            response = await page.goto(url, wait_until="networkidle", timeout=TIMEOUT_MS)
        status = response.status if response else 0

        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        await page.evaluate("window.scrollTo(0, 0)")

        await page.add_style_tag(content="""
            *, *::before, *::after {
                transition-duration: 0s !important;
                transition-delay: 0s !important;
                animation-duration: 0s !important;
                animation-delay: 0s !important;
                animation-iteration-count: 1 !important;
            }
            /* Fly-in panel flips display:none -> display:block at
               t=1s via setTimeout. Force visible so the panel is
               always stable at capture time. The JS that runs at
               panel show-time sets style="width: NNNpx" on the
               .inner-wrapper based on a width calculation that
               varies across captures (window.innerWidth read at
               different ticks); force both the panel and the wrapper
               to a fixed width so the text wraps to the same number
               of lines in every run. */
            #fly-in-notification-panel {
                display: block !important;
                opacity: 1 !important;
                width: 300px !important;
            }
            #fly-in-notification-panel .inner-wrapper {
                width: 280px !important;
            }
            /* #back-to-top-button is scroll-position-driven; its
               JS handler reads window.scrollY and toggles
               opacity / display. We scroll to bottom (to trigger
               lazy loads) then back to top, but the handler is
               debounced and races networkidle. Force always-hidden
               at capture time so the computed-style snapshot is
               stable; the button's DOM presence is still observable
               in dom.html. */
            #back-to-top-button {
                display: none !important;
                opacity: 0 !important;
            }
        """)

        ## Splide carousels auto-advance via window.requestAnimationFrame
        ## /setInterval; even with our transition-duration:0 override
        ## the active-slide index keeps rotating. Pause every Splide
        ## instance and rewind to slide 0 so the rendered list is
        ## deterministic. The Splide instance is stored on the host
        ## DOM element as `.splide` once init has finished.
        await page.evaluate("""
            () => {
                document.querySelectorAll('.splide').forEach(el => {
                    const inst = el.splide;
                    if (inst) {
                        try {
                            if (inst.Components && inst.Components.Autoplay) {
                                inst.Components.Autoplay.pause();
                            }
                            inst.go(0);
                        } catch (_) {}
                    }
                });
            }
        """)

        ## Force every loading=lazy image to load eagerly and wait for
        ## the result. Lazy images that race past networkidle leave
        ## getComputedStyle() seeing a 0-height placeholder in one
        ## capture and a fully sized image in the next; both panels
        ## anchored from a lazy image therefore jitter ~200px in
        ## height between runs. Promise.all settles once every image
        ## has fired onload or onerror; broken images won't block.
        await page.evaluate("""
            async () => {
                const imgs = Array.from(document.images);
                imgs.forEach(i => { if (i.loading === 'lazy') i.loading = 'eager'; });
                await Promise.all(imgs.map(i => i.complete ? null : new Promise(
                    r => { i.onload = i.onerror = r; }
                )));
            }
        """)
        await asyncio.sleep(0.3)

        html = await page.content()
        (page_dir / "dom.html").write_text(html, encoding="utf-8")

        await page.screenshot(
            path=str(page_dir / "screenshot.png"),
            full_page=False,
            animations="disabled",
        )

        ## Computed-style snapshot for the curated selector list.
        cstyles = await page.evaluate(
            """([selectors, props]) => {
                const out = {};
                for (const sel of selectors) {
                    let el;
                    try { el = document.querySelector(sel); } catch (_) { el = null; }
                    if (!el) { out[sel] = null; continue; }
                    const cs = getComputedStyle(el);
                    const o = {};
                    for (const p of props) {
                        o[p] = cs.getPropertyValue(p);
                    }
                    out[sel] = o;
                }
                return out;
            }""",
            [COMPUTED_STYLE_SELECTORS, COMPUTED_STYLE_PROPS],
        )
        (page_dir / "computed_styles.json").write_text(
            json.dumps(cstyles, indent=2, sort_keys=True), encoding="utf-8"
        )

        (page_dir / "console.json").write_text(
            json.dumps(console_events, indent=2, sort_keys=True), encoding="utf-8"
        )

        manifest_sorted = dict(sorted(manifest.items()))
        (page_dir / "manifest.json").write_text(
            json.dumps(manifest_sorted, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        ## Snapshot every form of browser-side state. Captured AFTER
        ## the page has fully settled.
        try:
            storage = await capture_storage(page, context)
            (page_dir / "storage.json").write_text(
                json.dumps(storage, indent=2, sort_keys=True, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            print(f"snapshot: storage capture failed for {label}: {exc}",
                  file=sys.stderr, flush=True)

        ## Iframe + Shadow DOM enumeration. The wiki currently uses
        ## neither, but a future template / extension might inject
        ## either. We want any new iframe URL or shadow root host to
        ## land in the diff as a visible regression rather than going
        ## unnoticed because nothing is sampling it.
        try:
            frame_shadow = await capture_iframes_shadow(page)
            (page_dir / "iframes_shadow.json").write_text(
                json.dumps(frame_shadow, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as exc:
            print(f"snapshot: iframe/shadow capture failed for {label}: {exc}",
                  file=sys.stderr, flush=True)

        ## Hover/focus state: trigger pointer over + keyboard focus on
        ## each selector and capture its computed style. Lets the diff
        ## catch theme regressions on :hover and :focus pseudo-classes
        ## that the static DOM snapshot can't see.
        if intent == "hover":
            try:
                hover = await capture_hover_styles(page)
                (page_dir / "hover_styles.json").write_text(
                    json.dumps(hover, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            except Exception as exc:
                print(f"snapshot: hover capture failed for {label}: {exc}",
                      file=sys.stderr, flush=True)

        ## postedit cleanup: revert the marker so the next capture
        ## starts from the same wikitext.
        if intent == "postedit":
            try:
                await _api_edit(context, BASE, safe, append_marker=False)
            except Exception:
                pass

        return (label, title, status, len(html))
    finally:
        await context.close()


async def capture_iframes_shadow(page) -> dict:
    """Walk the page for <iframe> elements and elements that have an
    attached shadowRoot. Records the iframe src URLs (so a new third-
    party embed lands in the diff) and the host selector + child count
    of every shadow root (so a new web-component is also caught).
    """
    return await page.evaluate("""
        () => {
            const iframes = Array.from(document.querySelectorAll('iframe'))
                .map(f => ({
                    src: f.getAttribute('src') || '',
                    sandbox: f.getAttribute('sandbox') || '',
                    title: f.getAttribute('title') || '',
                    loading: f.getAttribute('loading') || '',
                }));
            const hosts = [];
            const walk = root => {
                for (const el of root.querySelectorAll('*')) {
                    if (el.shadowRoot) {
                        const sel = el.tagName.toLowerCase()
                            + (el.id ? '#' + el.id : '')
                            + (el.classList.length
                               ? '.' + Array.from(el.classList).join('.')
                               : '');
                        hosts.push({
                            host_selector: sel,
                            mode: el.shadowRoot.mode || 'unknown',
                            child_count: el.shadowRoot.children.length,
                            text_length: (el.shadowRoot.textContent || '').length,
                        });
                        walk(el.shadowRoot);
                    }
                }
            };
            walk(document);
            return {iframes, shadow_roots: hosts};
        }
    """)


async def capture_hover_styles(page) -> dict:
    """For each curated selector, dispatch pointer move + keyboard focus
    over it, then capture the resulting computed style. Pure
    additive over the regular computed_styles capture -- this surfaces
    :hover and :focus pseudo-class theming.
    """
    out = {}
    for sel in HOVER_SELECTORS:
        try:
            handle = await page.query_selector(sel)
            if handle is None:
                out[sel] = None
                continue
            try:
                await handle.hover(timeout=2000)
            except Exception:
                pass
            try:
                await handle.focus(timeout=2000)
            except Exception:
                pass
            await asyncio.sleep(0.05)
            styles = await handle.evaluate(
                "(el, props) => { const cs = getComputedStyle(el); const o = {}; "
                "for (const p of props) o[p] = cs.getPropertyValue(p); return o; }",
                COMPUTED_STYLE_PROPS,
            )
            out[sel] = styles
        except Exception as exc:
            out[sel] = {"error": str(exc)}
        ## Move focus off the element so the next selector starts clean.
        try:
            await page.evaluate("() => document.activeElement && document.activeElement.blur()")
        except Exception:
            pass
    return out


async def main() -> int:
    modes = parse_modes()
    pages = load_pages()
    if not pages:
        print(f"no pages in {PAGES_FILE}", file=sys.stderr)
        return 1
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    print(
        f"mediawiki-dom-snapshot: base={BASE} pages={len(pages)} "
        f"modes={len(modes)} concurrency={CONCURRENCY} -> {RAW_DIR}/"
    )
    failures = 0
    ## Launch every requested browser once; capture_one() picks the one
    ## the mode_tuple names. Default BROWSERS=chromium so this is a
    ## single-launch in the common case.
    browser_names = _parse_browsers()
    async with async_playwright() as p:
        browser_instances = {}
        for b in browser_names:
            try:
                browser_instances[b] = await getattr(p, b).launch()
            except Exception as exc:
                print(f"snapshot: browser '{b}' launch failed: {exc}",
                      file=sys.stderr)
        sem = asyncio.Semaphore(CONCURRENCY)

        async def run_one(mode_tuple, title):
            async with sem:
                ## postedit only runs for the configured target pages.
                if mode_tuple[5] == "postedit" and title not in POSTEDIT_PAGES:
                    return True  ## silently skip
                browser = browser_instances.get(mode_tuple[6])
                if browser is None:
                    return True  ## browser failed to launch; skip
                try:
                    label, t, status, n = await capture_one(browser, mode_tuple, title)
                    if status == 0:
                        return True  ## skipped (e.g. postedit on wrong page)
                    tag = "OK  " if status == 200 else f"HTTP{status}"
                    print(f"  {tag}  {label:<55}  {t}  ({n} bytes)", flush=True)
                    return status == 200
                except Exception as exc:
                    print(
                        f"  FAIL  {mode_tuple[0]:<55}  {title}: {exc}",
                        file=sys.stderr, flush=True,
                    )
                    return False

        tasks = [run_one(m, t) for m in modes for t in pages]
        results = await asyncio.gather(*tasks)
        failures = sum(1 for r in results if not r)
        for b in browser_instances.values():
            await b.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
