#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Drive headless Chromium against a MediaWiki and dump a complete
regression-test corpus per page:

    RAW_DIR/<page>/
        dom.html          post-JS rendered HTML
        screenshot.png    1280x800 viewport screenshot (deterministic)
        manifest.json     URL -> {sha256, size, content_type, status}
        assets/<sha256>   raw asset body, indexed by content hash

This is enough to verify that *nothing* served to the browser changed
unexpectedly: the HTML diff catches structure changes, the manifest
diff catches every URL whose body content changed, the asset files
let you inspect the actual delta, and the screenshot pixel-diff
catches anything that renders differently regardless of the cause.

Env (read by the /usr/bin/mediawiki-dom-snapshot wrapper):
  BASE_URL    target wiki origin              default https://www.kicksecure.com
  RAW_DIR     destination root                default /var/lib/mediawiki-dom-snapshot/raw
  PAGES_FILE  one title per line              default /etc/mediawiki-dom-snapshot/pages.conf
  VIEWPORT    "WIDTHxHEIGHT"                  default 1280x800
  TIMEOUT_MS  per-page timeout, milliseconds  default 30000
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
W, H = (int(x) for x in os.environ.get("VIEWPORT", "1280x800").split("x"))
TIMEOUT_MS = int(os.environ.get("TIMEOUT_MS", "30000"))


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
    """Pick a file extension so each asset is browsable by humans.
    Falls back to .bin when nothing matches.
    """
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    ## Common explicit cases (mimetypes.guess_extension is hit-or-miss).
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
    ## Last resort: URL suffix.
    suffix = Path(url.split("?", 1)[0]).suffix.lower()
    if suffix and len(suffix) <= 6:
        return suffix
    return ".bin"


async def snapshot_one(browser, title: str) -> tuple[str, int, int]:
    """Capture dom.html + screenshot.png + manifest.json + assets/* for one page."""
    page_dir = RAW_DIR / safe_name(title)
    assets_dir = page_dir / "assets"
    page_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)

    ## Fresh context per page so cookies set by one page don't leak into
    ## the next render and shift its server-side metadata.
    context = await browser.new_context(
        viewport={"width": W, "height": H},
        ignore_https_errors=True,
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 "
            "mediawiki-dom-snapshot/0.2"
        ),
    )
    page = await context.new_page()

    ## Collect every response that arrives during the load. We index
    ## entries by URL (which is what the HTML refers to) but the
    ## de-duplication / equality key is the content sha256.
    manifest: dict[str, dict] = {}

    async def on_response(response):
        url = response.url
        if url in manifest:
            return  ## first-wins; second visit's responses replay from cache
        try:
            body = await response.body()
        except Exception as exc:
            manifest[url] = {"error": f"body unavailable: {exc}"}
            return
        digest = sha256_hex(body)
        ct = response.headers.get("content-type", "")
        ext = ext_for(ct, url)
        asset_path = assets_dir / f"{digest}{ext}"
        ## Write asset once; the same content from different URLs
        ## de-duplicates onto a single file.
        if not asset_path.exists():
            asset_path.write_bytes(body)
        manifest[url] = {
            "sha256": digest,
            "size": len(body),
            "content_type": ct,
            "status": response.status,
            "asset": asset_path.name,
        }

    page.on("response", lambda response: asyncio.create_task(on_response(response)))

    safe = title.replace(" ", "_")
    url = f"{BASE}/wiki/{safe}"
    api = f"{BASE}/w/api.php"
    try:
        ## Force a fresh parse so each run starts from the same state.
        try:
            await page.request.post(
                api,
                form={"action": "purge", "format": "json", "titles": safe},
                timeout=TIMEOUT_MS,
            )
        except Exception:
            pass
        ## Two visits: first warms server-side caches, second observes
        ## the stable steady state.
        for _ in range(2):
            response = await page.goto(url, wait_until="networkidle", timeout=TIMEOUT_MS)
        status = response.status if response else 0
        ## Settle scroll-spy widgets.
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        await page.evaluate("window.scrollTo(0, 0)")
        ## Give pending on_response coroutines a tick to finish.
        await asyncio.sleep(0.2)

        html = await page.content()
        (page_dir / "dom.html").write_text(html, encoding="utf-8")

        ## Full-page screenshot is a stronger reference than viewport-
        ## only, but its height varies by content. Use viewport for
        ## comparable pixel diffs across runs at the same wiki state.
        await page.screenshot(
            path=str(page_dir / "screenshot.png"),
            full_page=False,
            animations="disabled",
        )

        ## Write manifest sorted by URL for stable diffs.
        manifest_sorted = dict(sorted(manifest.items()))
        (page_dir / "manifest.json").write_text(
            json.dumps(manifest_sorted, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        return (title, status, len(html))
    finally:
        await context.close()


async def main() -> int:
    pages = load_pages()
    if not pages:
        print(f"no pages in {PAGES_FILE}", file=sys.stderr)
        return 1
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    print(
        f"mediawiki-dom-snapshot: base={BASE} viewport={W}x{H} "
        f"pages={len(pages)} -> {RAW_DIR}/"
    )
    failures = 0
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        for title in pages:
            try:
                t, status, n = await snapshot_one(browser, title)
                tag = "OK  " if status == 200 else f"HTTP{status}"
                print(f"  {tag}  {t}  ({n} bytes html)", flush=True)
                if status != 200:
                    failures += 1
            except Exception as exc:
                print(f"  FAIL  {title}: {exc}", file=sys.stderr, flush=True)
                failures += 1
        await browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
