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

VIEWPORTS = {
    "desktop": (1280, 800),
    "mobile": (390, 844),
}

## Build the full 16-element mode list as (label, auth, visit, vp, scheme) tuples.
def _all_modes() -> list[tuple]:
    out = []
    for auth in ("anon", "user"):
        for visit in ("first", "repeat"):
            for vp in ("desktop", "mobile"):
                for scheme in ("light", "dark"):
                    label = f"{auth}-{visit}-{vp}-{scheme}"
                    out.append((label, auth, visit, vp, scheme))
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


async def capture_one(browser, mode_tuple, title: str) -> tuple[str, str, int, int]:
    label, auth, visit, vp_name, scheme = mode_tuple
    page_dir = RAW_DIR / safe_name(title) / label
    page_dir.mkdir(parents=True, exist_ok=True)
    W, H = VIEWPORTS[vp_name]

    context = await browser.new_context(
        viewport={"width": W, "height": H},
        ignore_https_errors=True,
        color_scheme=scheme,
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 "
            "mediawiki-dom-snapshot/0.4"
        ),
    )

    if auth == "user":
        if not await login(context, BASE, WIKI_USER, WIKI_PASSWORD):
            await context.close()
            raise RuntimeError(f"login failed for mode {label}")

    page = await context.new_page()
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
    url = f"{BASE}/wiki/{safe}"
    api = f"{BASE}/w/api.php"
    try:
        try:
            await page.request.post(
                api,
                form={"action": "purge", "format": "json", "titles": safe},
                timeout=TIMEOUT_MS,
            )
        except Exception:
            pass

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
               always stable at capture time. */
            #fly-in-notification-panel {
                display: block !important;
                opacity: 1 !important;
                width: 300px !important;
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

        return (label, title, status, len(html))
    finally:
        await context.close()


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
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        sem = asyncio.Semaphore(CONCURRENCY)

        async def run_one(mode_tuple, title):
            async with sem:
                try:
                    label, t, status, n = await capture_one(browser, mode_tuple, title)
                    tag = "OK  " if status == 200 else f"HTTP{status}"
                    print(f"  {tag}  {label:<35}  {t}  ({n} bytes)", flush=True)
                    return status == 200
                except Exception as exc:
                    print(
                        f"  FAIL  {mode_tuple[0]:<35}  {title}: {exc}",
                        file=sys.stderr, flush=True,
                    )
                    return False

        tasks = [run_one(m, t) for m in modes for t in pages]
        results = await asyncio.gather(*tasks)
        failures = sum(1 for r in results if not r)
        await browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
