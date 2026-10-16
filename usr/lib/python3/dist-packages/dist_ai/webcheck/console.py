## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Runtime gate: NO page emits a JS console error, an uncaught page exception, or a
Content-Security-Policy violation when loaded in a real browser.

Generic webcheck lane, shared by the family Pages sites and the wiki stage sites. A CSP
regression (an inline handler, a new CDN, a wrong sha256), a broken/renamed asset, or a
throwing script renders a VISIBLY broken page -- yet passes every STATIC check, because none
of them run the page's JavaScript. This gate does: it loads each page in headless chromium
and FAILS (exit 1) if ANY page produces:

  - a console message at `error` level (page.on("console")), including a failed subresource load,
  - an uncaught exception (page.on("pageerror")), or
  - a `securitypolicyviolation` DOM event (captured via an init script).

Two page-source models share the one async core `check(base, paths, ...)`:
  - FAMILY (local): `check_roots(roots)` serves each site checkout from a localhost mount
    (reusing mobile.py's harness) and points `base` at it -- the model the website-tests
    browser lanes use. No network, no external build.
  - STAGE (served): `main()` drives `--base <url> --paths/--paths-file/--enumerate-from`
    against an already-served build (the public stage deploy or a docker preview).

Transient-blip resistance: against a LIVE host a one-off 5xx/network hiccup on a subresource is
not a site defect, so a page that produces hits is RE-PROBED up to --retries times; it passes the
moment an attempt is clean, and fails only if hits PERSIST. A deterministic fault (a CSP
violation, a thrown exception, a 404 asset) reproduces every attempt and still fails.

Capture model: an init-script records each securitypolicyviolation to a page-global array,
harvested after settle and flushed in a finally so a later crash cannot lose an early violation.
Needs a browser; against untrusted input it runs CONFINED in the sandbox. The browser-free logic
(allowlist, hit classification, URL join, off-origin, path enumeration) is unit-tested.
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from dist_ai.webcheck.mobile import (
    _MountHandler, _MountingTCPServer, _page_urls, _skip, SUBSITES)

# Genuinely-benign console/CSP noise to suppress, as compiled regexes matched against each
# captured message (console text, pageerror text, or a formatted CSP violation). EMPTY on
# purpose: a strict CSP with self-hosted assets should produce ZERO noise on a clean page, so
# every hit is a real defect to fix at the root. Add an entry ONLY for noise proven benign, each
# with an inline comment naming WHY it is benign and cannot mask a real regression -- never to
# silence a finding that should be fixed.
_BENIGN_ALLOWLIST: list[re.Pattern[str]] = [
]


def is_allowlisted(message: str) -> bool:
    """True when a captured hit matches a documented benign-noise pattern and must be
    suppressed. Empty allowlist -> always False, so every hit counts (fail-closed)."""
    return any(pat.search(message) for pat in _BENIGN_ALLOWLIST)


def is_off_origin(final_url: str, base_url: str) -> bool:
    """True when a page ended up on a DIFFERENT HOST than the base -- a meta-refresh stub that
    redirects to a third-party site. Such a page's console/CSP answers a question about that
    site, not ours, so the caller reports it external.

    Compares the lowercased HOST only -- the host is the site identity here. A same-host scheme
    upgrade (http->https, which GitHub Pages 301s) or an explicit-vs-implicit default port
    (https://host:443 vs https://host) is still OUR content and must be gated; distinguishing by
    scheme or port would read those as off-origin and SKIP the check (a fail-OPEN). Chromium
    lowercases the host in page.url, so a non-canonical base host still matches; reading only
    `.hostname` (never `.port`) also avoids a ValueError on a malformed base port."""
    return (urlsplit(final_url).hostname or "").lower() \
        != (urlsplit(base_url).hostname or "").lower()


def page_url(base: str, path: str) -> str:
    """Join the base origin and a page path, tolerating a path given without its leading slash
    (a bare `base + path` yields `http://hostwiki/...`, which Playwright cannot load -- so the
    page gets mis-reported as a wedge and the gate fails on a typo). Idempotent for rooted
    paths."""
    return base.rstrip("/") + "/" + path.lstrip("/")


# Registered via add_init_script BEFORE any page script runs, so a violation fired by the
# page's own inline/early markup is captured. Records a structured payload per event onto a
# page-global array, harvested after the page settles.
_CSP_INIT_SCRIPT = """
window.__cspViolations = [];
document.addEventListener('securitypolicyviolation', function (e) {
  window.__cspViolations.push({
    directive: e.effectiveDirective || e.violatedDirective || '',
    blockedURI: e.blockedURI || 'inline',
    disposition: e.disposition || '',
    sourceFile: e.sourceFile || '',
    line: e.lineNumber || 0
  });
});
"""


def format_csp(v: dict) -> str:
    """One actionable line per CSP violation: which directive blocked what, and where."""
    where = ""
    if v.get("sourceFile"):
        where = f" @ {v['sourceFile']}:{v.get('line', 0)}"
    return f"{v.get('directive', '?')} blocked {v.get('blockedURI', 'inline')}{where}"


def attempts_for(retries: int) -> int:
    """Total probe attempts for a `--retries` value, clamped so at least ONE probe always runs.
    argparse accepts any int (no minimum), so a negative --retries must not make range(1,
    retries+1) empty -- a zero-probe loop would report every page 'ok' without ever loading it
    (a fail-open). Pure, so the clamp is unit-tested without a browser."""
    return max(1, retries + 1)


def classify_hits(res: dict) -> list[tuple[str, str]]:
    """Reduce one page's captured evidence to the non-allowlisted hits as (kind, detail) pairs.
    Pure (no browser), so the console/pageerror/CSP -> allowlist -> finding mapping is unit
    tested directly."""
    hits: list[tuple[str, str]] = []
    for text in res.get("console", []):
        if not is_allowlisted(text):
            hits.append(("console", text))
    for text in res.get("pageerror", []):
        if not is_allowlisted(text):
            hits.append(("pageerror", text))
    for v in res.get("csp", []):
        detail = format_csp(v)
        if not is_allowlisted(detail):
            hits.append(("csp", detail))
    return hits


async def _probe(browser, url: str, settle_ms: int, base_url: str) -> dict:
    """Load one page and collect its console errors, page errors, and CSP violations. Its own
    close is time-boxed so a wedged page cannot hang here -- the caller ALSO wraps this in a
    hard wall-clock timeout."""
    console_errors: list[str] = []
    page_errors: list[str] = []

    def on_console(m) -> None:
        if m.type != "error":
            return
        # A failed-resource console error names the resource only in msg.location, not the
        # text ("Failed to load resource: ... 404"); append it so the finding is actionable.
        loc = m.location or {}
        res_url = loc.get("url") or ""
        text = m.text
        if res_url and res_url not in text:
            text = f"{text} [{res_url}]"
        console_errors.append(text)

    page = await browser.new_page()
    # Register captures BEFORE navigation so nothing fired during initial load is missed.
    page.on("console", on_console)
    page.on("pageerror", lambda e: page_errors.append(str(e)))
    await page.add_init_script(_CSP_INIT_SCRIPT)
    csp: list[dict] = []
    try:
        resp = await page.goto(url, wait_until="networkidle", timeout=45000)
        # Playwright does NOT raise on a 404/500; without this a served error page reads as
        # ok and masks a missing/broken page (whose own console errors we would also miss).
        status = resp.status if resp is not None else 0
        if status < 200 or status >= 400:
            return {"status": status}
        await page.wait_for_timeout(settle_ms)
        # A meta-refresh redirect off OUR origin lands on a third-party page; its console is
        # not ours to gate. The console/pageerror listeners stay attached across the redirect, so
        # the captured lists also hold the DESTINATION's errors (a legit stub -> a noisy
        # production page would false-fail); report the external redirect, not a false finding.
        if is_off_origin(page.url, base_url):
            return {"external": page.url}
        csp_harvest_failed = False
        try:
            csp = await page.evaluate("window.__cspViolations || []")
            if not isinstance(csp, list):
                # The page reassigned window.__cspViolations to a non-array -> the harvest is
                # untrustworthy; do NOT read it as "no violations" (that would be a fail-open).
                csp_harvest_failed = True
                csp = []
        except Exception:
            # evaluate throws when the execution context was destroyed (a navigation fired
            # during/after settle, or the renderer crashed). Any CSP violation that fired on
            # THIS document is then lost (the next document's array starts empty), so this is
            # NOT clean -- flag it so the caller re-probes and, if it persists, fails rather
            # than silently passing. (console/pageerror captured by the listeners still stand.)
            csp_harvest_failed = True
        return {"status": status, "console": console_errors, "pageerror": page_errors,
                "csp": csp, "csp_harvest_failed": csp_harvest_failed}
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=5)
        except Exception:
            pass


async def check(base: str, paths: list[str], settle_ms: int, hard_timeout: int = 55,
                retries: int = 2) -> int:
    from playwright.async_api import async_playwright

    hits: list[tuple[str, str, str]] = []  # (path, kind, detail)
    bad_status: list[tuple[str, int]] = []
    wedged: list[str] = []
    external: list[str] = []
    inconclusive: list[str] = []
    attempts = attempts_for(retries)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        for path in paths:
            url = page_url(base, path)
            # Re-probe a failing page up to `attempts` times: pass on the FIRST clean attempt,
            # keep only the LAST attempt's outcome otherwise. A transient live-host blip clears
            # on retry; a deterministic fault persists and still fails.
            outcome: dict = {}
            for attempt in range(1, attempts + 1):
                try:
                    # Hard wall-clock cap ABOVE playwright's own 45s: a wedged CDP/browser can
                    # outlast the internal timeout, so this asyncio-level kill bounds each page.
                    res = await asyncio.wait_for(
                        _probe(browser, url, settle_ms, base), timeout=hard_timeout)
                except Exception:
                    # This page wedged -> recreate the browser so the wedge does not cascade,
                    # then retry (a hung load is often transient too).
                    try:
                        await asyncio.wait_for(browser.close(), timeout=5)
                    except Exception:
                        pass
                    browser = await p.chromium.launch()
                    outcome = {"wedged": True}
                    if attempt < attempts:
                        print(f"RETRY     {path} (attempt {attempt} wedged)", flush=True)
                        continue
                    break
                if "external" in res:
                    outcome = res  # terminal, not a fault -> never retried
                    break
                status = res.get("status", 0)
                if status < 200 or status >= 400:
                    outcome = {"bad_status": status}
                    if attempt < attempts:
                        print(f"RETRY     {path} (attempt {attempt}: HTTP {status})", flush=True)
                        continue
                    break
                page_hits = classify_hits(res)
                if page_hits:
                    outcome = {"hits": page_hits}
                    if attempt < attempts:
                        print(f"RETRY     {path} (attempt {attempt}: {len(page_hits)} hit(s), "
                              f"re-probing for a transient blip)", flush=True)
                        continue
                    break
                if res.get("csp_harvest_failed"):
                    # Could not read the CSP array (context destroyed / crash / poisoned) and no
                    # console/pageerror hit either -> cannot CONFIRM clean. Re-probe; if it never
                    # resolves, count it (never silently pass).
                    outcome = {"inconclusive": True}
                    if attempt < attempts:
                        print(f"RETRY     {path} (attempt {attempt}: CSP harvest failed)",
                              flush=True)
                        continue
                    break
                outcome = {"clean": True}
                break

            if "external" in outcome:
                print(f"REDIR-EXT {path} -> {outcome['external']}", flush=True)
                external.append(path)
                continue
            if outcome.get("wedged"):
                print(f"TIMEOUT   {path}", flush=True)
                wedged.append(path)
                continue
            if outcome.get("inconclusive"):
                print(f"NO-EVAL   {path} (CSP harvest failed every attempt -- not clean)",
                      flush=True)
                inconclusive.append(path)
                continue
            if "bad_status" in outcome:
                print(f"HTTP {outcome['bad_status']:<4} {path}", flush=True)
                bad_status.append((path, outcome["bad_status"]))
                continue
            page_hits = outcome.get("hits", [])
            print(f"{'HIT' if page_hits else 'ok':9} {len(page_hits):>3} {path}", flush=True)
            for kind, detail in page_hits:
                print(f"          -> {kind}: {detail[:200]}", flush=True)
                hits.append((path, kind, detail))
        try:
            await asyncio.wait_for(browser.close(), timeout=5)
        except Exception:
            pass

    print(f"\n{len(paths)} page(s) checked; {len(hits)} console/pageerror/CSP hit(s), "
          f"{len(bad_status)} bad status, {len(wedged)} wedged, "
          f"{len(inconclusive)} inconclusive, {len(external)} external-redirect.")
    # Every page redirected off-origin -> NOTHING on our site was actually gated (almost always
    # a wrong base whose origin never matches page.url). A hollow "0 hits" is not a pass.
    if paths and len(external) == len(paths):
        print("ERROR: every page redirected off-origin -- nothing was gated; check the base",
              flush=True)
        return 1
    return 1 if (hits or bad_status or wedged or inconclusive) else 0


def check_roots(roots: list[str], settle_ms: int = 1000, hard_timeout: int = 55,
                retries: int = 2) -> int:
    """FAMILY entry: serve each local site checkout from a localhost mount (reusing mobile.py's
    harness, incl. SUBSITES mounting) and run the console gate against it. SKIPs (exit 77) when
    Playwright/chromium is absent, exactly like the sibling browser lanes."""
    import os
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401  (engine launch is inside check())
    except ImportError:
        _skip('python3-playwright not installed')

    by_name = {os.path.basename(r): r for r in roots}
    # Group into docroots exactly like mobile.main(): a subsite is mounted under its parent's
    # docroot at its mount path (skipped if the parent is not checked out).
    docroots: dict[str, dict] = {}
    for root in roots:
        name = os.path.basename(root)
        sub = SUBSITES.get(name)
        if sub:
            parent_name, mount = sub
            parent = by_name.get(parent_name)
            if not parent:
                sys.stdout.write('  ....  %s skipped (parent %s not checked out)\n'
                                 % (name, parent_name))
                continue
            entry = docroots.setdefault(parent, {'mounts': {}, 'urls': []})
            entry['mounts'][mount] = root
            entry['urls'] += _page_urls(root, mount)
        else:
            entry = docroots.setdefault(root, {'mounts': {}, 'urls': []})
            entry['urls'] += _page_urls(root, '')

    overall = 0
    for docroot, entry in docroots.items():
        handler = functools.partial(_MountHandler, directory=docroot)
        httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
        httpd.mounts = entry['mounts']
        port = httpd.server_address[1]
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            base = 'http://127.0.0.1:%d' % port
            paths = sorted(set(entry['urls']))
            if asyncio.run(check(base, paths, settle_ms, hard_timeout, retries)) != 0:
                overall = 1
        finally:
            httpd.shutdown()
    return overall


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True,
                    help="served site origin, e.g. https://kicksecure-stage.github.io")
    ap.add_argument("--settle", type=int, default=1000,
                    help="post-load settle time in ms (lets async widget/subresource "
                         "violations fire before harvest; default 1000)")
    # Exactly one page-source mode: a required mutually-exclusive group makes "two modes" and
    # "no mode" explicit argparse errors.
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--paths", nargs="*", default=None, help="explicit page paths to check")
    src.add_argument("--paths-file", type=Path, default=None,
                     help="file with one path per line (for a full sweep run inside the "
                          "sandbox, where the built tree is not present: enumerate on the "
                          "host, stage this)")
    src.add_argument("--enumerate-from", type=Path, default=None,
                     help="a built tree dir; check root + every wiki/<Page>/")
    ap.add_argument("--hard-timeout", type=int, default=55,
                    help="per-page wall-clock cap (s); a wedged page is reported + the browser "
                         "recreated, so a full sweep can't stall (default 55, above the 45s goto)")
    ap.add_argument("--retries", type=int, default=2,
                    help="extra re-probes of a FAILING page before counting it (default 2 -> up "
                         "to 3 attempts); absorbs a transient live-host blip, keeps a "
                         "deterministic fault failing. 0 disables.")
    return ap


def enumerate_paths(tree: Path) -> list[str]:
    """Every built page under the FLAT tree: root index.html -> "/", and every wiki/<...>.html
    served at the extensionless /wiki/<...> (no .html, no trailing slash -- both 404 on the
    served tree). Recursive, so a nested title like wiki/Dev/wikitest.html is included."""
    paths = ["/"] if (tree / "index.html").is_file() else []
    wiki = tree / "wiki"
    for page in sorted(wiki.rglob("*.html")):
        if page.is_file():
            paths.append("/wiki/" + page.relative_to(wiki).as_posix().removesuffix(".html"))
    return paths


def main() -> int:
    ap = build_parser()
    args = ap.parse_args()

    if args.enumerate_from:
        paths = enumerate_paths(args.enumerate_from)
    elif args.paths_file:
        paths = [ln.strip() for ln in args.paths_file.read_text().splitlines() if ln.strip()]
    else:
        # the required mutually-exclusive group guarantees --paths is set here
        paths = args.paths
    if not paths:
        ap.error("no pages to check")
    return asyncio.run(check(args.base, paths, args.settle, args.hard_timeout, args.retries))


if __name__ == "__main__":
    sys.exit(main())
