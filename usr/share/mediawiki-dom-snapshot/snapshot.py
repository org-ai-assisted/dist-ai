#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Drive headless Chromium against a MediaWiki and dump post-JS DOM per page.

Env (all set by the /usr/bin/mediawiki-dom-snapshot wrapper):
  BASE_URL    target wiki origin              default https://www.kicksecure.com
  RAW_DIR     destination for *.html dumps    default /var/lib/mediawiki-dom-snapshot/raw
  PAGES_FILE  one title per line              default /etc/mediawiki-dom-snapshot/pages.conf
  VIEWPORT    "WIDTHxHEIGHT"                  default 1280x800
  TIMEOUT_MS  per-page timeout, milliseconds  default 30000
"""
import asyncio
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


async def snapshot_one(browser, title: str) -> tuple[str, int, int]:
    ## Fresh context per page so cookies set by one page don't leak into
    ## the next render and shift its server-side metadata (og:*,
    ## schema.org @type, title suffix, ...). MediaWiki + extensions key
    ## some of these on session.
    context = await browser.new_context(
        viewport={"width": W, "height": H},
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 "
            "mediawiki-dom-snapshot/0.1"
        ),
    )
    page = await context.new_page()
    safe = title.replace(" ", "_")
    url = f"{BASE}/wiki/{safe}"
    api = f"{BASE}/w/api.php"
    try:
        ## Force a fresh parse so each run starts from the same state.
        ## Without this the FIRST hit of a session populates the parser
        ## cache and the SECOND hit reads back a richer/different render
        ## (og:description, JSON-LD @type=website vs Article, ...).
        try:
            await page.request.post(
                api,
                form={"action": "purge", "format": "json", "titles": safe},
                timeout=TIMEOUT_MS,
            )
        except Exception:
            ## purge fails on Special: pages (no parser output). Tolerate.
            pass
        ## Visit the page TWICE. The first visit warms server-side parser
        ## caches and lets MediaWiki's deferred-render extensions
        ## (Description2 for og:description, schema.org @type upgrade, ...)
        ## settle. The second visit observes the stable steady-state.
        for _ in range(2):
            response = await page.goto(url, wait_until="networkidle", timeout=TIMEOUT_MS)
        status = response.status if response else 0
        ## Trigger any lazy/scroll-spy widgets, then settle again.
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except Exception:
            pass
        await page.evaluate("window.scrollTo(0, 0)")
        html = await page.content()
        (RAW_DIR / f"{safe_name(title)}.html").write_text(html, encoding="utf-8")
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
                print(f"  {tag}  {t}  ({n} bytes)", flush=True)
                if status != 200:
                    failures += 1
            except Exception as exc:
                print(f"  FAIL  {title}: {exc}", file=sys.stderr, flush=True)
                failures += 1
        await browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
