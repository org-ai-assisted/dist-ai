#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Drive headless Chromium against a MediaWiki and dump a complete
regression-test corpus per page-and-mode:

    RAW_DIR/<page>/<mode>/
        dom.html          post-JS rendered HTML
        screenshot.png    1280x800 viewport screenshot (deterministic)
        manifest.json     URL -> {sha256, size, status, content_type, headers}
        assets/<sha256>.<ext>
                          raw asset body, indexed by content hash

Modes captured:
    anon-first      fresh anonymous context, single visit (cold server
                    parser cache, cold browser cache).
    anon-repeat     fresh anonymous context, purge + warmup visit +
                    steady-state visit. The historical default; captures
                    the "user has been here before" state.
    user-first      authenticated context (cookies from WIKI_USER login),
                    single visit.
    user-repeat     authenticated context, purge + warmup + steady-state.

Env:
  BASE_URL        target wiki origin                default https://www.kicksecure.com
  RAW_DIR         destination root                  default /var/lib/mediawiki-dom-snapshot/raw
  PAGES_FILE      one title per line                default /etc/mediawiki-dom-snapshot/pages.conf
  VIEWPORT        "WIDTHxHEIGHT"                    default 1280x800
  TIMEOUT_MS      per-page timeout, milliseconds    default 30000
  CAPTURE_MODES   comma-separated subset of the     default anon-first,anon-repeat
                  four modes, or "all"
  WIKI_USER       username for logged-in modes;     default (unset, skip user-* modes)
                  must be paired with WIKI_PASSWORD
  WIKI_PASSWORD   password for logged-in modes
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

WIKI_USER = os.environ.get("WIKI_USER", "")
WIKI_PASSWORD = os.environ.get("WIKI_PASSWORD", "")

ALL_MODES = ["anon-first", "anon-repeat", "user-first", "user-repeat"]


def parse_modes() -> list[str]:
    raw = os.environ.get("CAPTURE_MODES", "anon-first,anon-repeat").strip()
    if raw == "all":
        return list(ALL_MODES)
    modes = [m.strip() for m in raw.split(",") if m.strip()]
    for m in modes:
        if m not in ALL_MODES:
            raise SystemExit(f"snapshot: unknown CAPTURE_MODES entry: {m}")
    if any(m.startswith("user-") for m in modes) and not (WIKI_USER and WIKI_PASSWORD):
        print(
            "snapshot: WIKI_USER/WIKI_PASSWORD unset; user-* modes will be skipped",
            file=sys.stderr,
        )
        modes = [m for m in modes if not m.startswith("user-")]
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
    """Authenticate against MediaWiki's API and inject the resulting
    session cookies into the browser context. Returns True on success.

    Uses the action=login flow (clientlogin + lgtoken) rather than
    the Special:UserLogin web form because it's robust against skin
    changes and doesn't require parsing HTML for the CSRF token.
    """
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


async def capture_one(browser, mode: str, title: str) -> tuple[str, int, int]:
    """Capture dom.html + screenshot + manifest + assets for one (page, mode)."""
    page_dir = RAW_DIR / safe_name(title) / mode
    page_dir.mkdir(parents=True, exist_ok=True)

    auth = mode.startswith("user-")
    repeat = mode.endswith("-repeat")

    context = await browser.new_context(
        viewport={"width": W, "height": H},
        ignore_https_errors=True,
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 "
            "mediawiki-dom-snapshot/0.3"
        ),
    )

    if auth:
        if not await login(context, BASE, WIKI_USER, WIKI_PASSWORD):
            await context.close()
            raise RuntimeError(f"login failed for mode {mode}")

    page = await context.new_page()
    manifest: dict[str, dict] = {}
    page.on("response", lambda r: asyncio.create_task(
        record_response_factory(page_dir, manifest)(r)
    ))

    safe = title.replace(" ", "_")
    url = f"{BASE}/wiki/{safe}"
    api = f"{BASE}/w/api.php"
    try:
        ## Server parser cache: purge before EVERY mode so the visit-count
        ## comparison is apples-to-apples (one purge then one visit, or
        ## one purge then two visits).
        try:
            await page.request.post(
                api,
                form={"action": "purge", "format": "json", "titles": safe},
                timeout=TIMEOUT_MS,
            )
        except Exception:
            pass

        n_visits = 2 if repeat else 1
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
        """)
        await asyncio.sleep(0.3)

        html = await page.content()
        (page_dir / "dom.html").write_text(html, encoding="utf-8")

        await page.screenshot(
            path=str(page_dir / "screenshot.png"),
            full_page=False,
            animations="disabled",
        )

        manifest_sorted = dict(sorted(manifest.items()))
        (page_dir / "manifest.json").write_text(
            json.dumps(manifest_sorted, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        return (title, status, len(html))
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
        f"mediawiki-dom-snapshot: base={BASE} viewport={W}x{H} "
        f"pages={len(pages)} modes={','.join(modes)} -> {RAW_DIR}/"
    )
    failures = 0
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        for mode in modes:
            print(f"\n  === mode: {mode} ===", flush=True)
            for title in pages:
                try:
                    t, status, n = await capture_one(browser, mode, title)
                    tag = "OK  " if status == 200 else f"HTTP{status}"
                    print(f"  {tag}  {mode}  {t}  ({n} bytes html)", flush=True)
                    if status != 200:
                        failures += 1
                except Exception as exc:
                    print(f"  FAIL  {mode}  {title}: {exc}", file=sys.stderr, flush=True)
                    failures += 1
        await browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
