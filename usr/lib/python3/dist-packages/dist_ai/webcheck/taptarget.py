#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""WCAG 2.5.8 Target Size (Minimum, AA) geometric gate: no UNDERSIZED, UNDER-SPACED,
NON-EXEMPT tap target.

Why this exists SEPARATELY from the axe lane (webcheck.axe already enables axe-core's
`target-size` rule): axe honours WCAG 2.5.8's INLINE exception -- a link that sits in a run of
sentence text is exempt, and axe does not flag it. That is correct, but it means a link which is
the WHOLE content of a list item or a table cell (a forum/archive link list, a cell that is just a
link) -- NOT in a sentence, genuinely a standalone target -- is treated by axe the same as a prose
link and slips through when it is undersized AND crowded against its neighbours. Lighthouse flags
the whole family (it applies no inline exception, so it ALSO over-reports the exempt sentence
links). This lane threads the needle: it reproduces WCAG 2.5.8 exactly -- the inline-in-sentence
link stays exempt, the standalone undersized+crowded link FAILS.

The rule (https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum):
a target under 24x24 CSS px fails UNLESS one of:
  - Spacing: a 24px-diameter circle centred on it intersects no other target's box and no other
    undersized target's circle (so an isolated small link passes; a stack of small links does not).
  - Inline: the target is in a sentence / its size is constrained by the line-height of
    surrounding non-target text (a prose link). Honoured here as `standalone == False`.
(The equivalent-control, user-agent and essential exceptions are not expressible from geometry and
are out of scope -- a genuine one would be a baseline concern, but none applies to the wiki link
lists this guards.)

The GEOMETRY engine (classify / evaluate) is PURE and browser-free -- unit-tested directly in
check_taptarget_test.py with no browser. The browser side only EXTRACTS raw rectangles + the
standalone flag per page (TAPTARGET_JS); Python does every size/spacing decision, so the whole
verdict is testable without Playwright. This mirrors webcheck.axe's extract-in-browser /
decide-in-Python split.

Measured at BOTH a phone and a desktop viewport (VIEWPORTS): the stacking that crowds small links
is width-dependent, and a link list that wraps to one column on a phone can sit as a tight inline
row on desktop, so a single viewport under-reports.

Needs a real browser (Playwright + chromium), so like check_mobile.py / check_width.py it SKIPs
(exit 77) when the browser is unavailable, and shares that module's page-discovery + HTTP mount
harness. Usage: taptarget.py <site-root> [<site-root> ...]  (or via check_taptarget.py).
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import math
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dist_ai.webcheck.mobile import (
    _MountHandler, _MountingTCPServer, _page_urls, _skip, SUBSITES)

# WCAG 2.5.8 AA minimum target edge / circle diameter, in CSS px.
MIN_PX = 24.0
# (name, width, height). The crowding that fails 2.5.8 is width-dependent, so sweep a phone AND a
# desktop width -- a column of links on the phone can be a tight inline row on desktop.
VIEWPORTS: Tuple[Tuple[str, int, int], ...] = (("mobile", 390, 844), ("desktop", 1280, 900))
# Post-load settle before measuring, ms (fonts/webfont swap can nudge a line box height).
SETTLE_MS = 400
# Per-page hard wall-clock, s (mirrors axe.check's hard_timeout rationale).
HARD_TIMEOUT = 45
_CTRL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _safe_terminal(s: str) -> str:
    """Strip C0/C1 control chars from page-derived text before it reaches the operator's terminal
    (a selector/href is page content even on our own sites) -- mirrors webcheck.axe / console."""
    return _CTRL_CHARS.sub('?', s)


# A candidate / neighbour tap target, as the browser reports it. Pure data: the geometry engine
# below works on these alone, so it is unit-tested with hand-built dicts and no browser.
#   x,y,w,h    : getBoundingClientRect (CSS px, viewport-relative)
#   candidate  : a CONTENT link that this lane JUDGES (vs a neighbour considered only for spacing)
#   standalone : the link is NOT inline-in-sentence (its text block holds no other real text) --
#                only a standalone candidate can fail; an inline one is WCAG-exempt
#   sel, href  : for a readable failure line
Record = Dict[str, Any]


def _center(rec: Record) -> Tuple[float, float]:
    return rec["x"] + rec["w"] / 2.0, rec["y"] + rec["h"] / 2.0


def _circle_hits_rect(cx: float, cy: float, radius: float, rec: Record) -> bool:
    """A circle (centre cx,cy, given radius) intersects a rectangle's area. Distance from the
    centre to the rect, clamped per-axis; closer than radius => intersect. Used for the 2.5.8
    'circle must not intersect another TARGET' half of the spacing test."""
    nx = min(max(cx, rec["x"]), rec["x"] + rec["w"])
    ny = min(max(cy, rec["y"]), rec["y"] + rec["h"])
    return math.hypot(cx - nx, cy - ny) < radius


def is_undersized(rec: Record, min_px: float = MIN_PX) -> bool:
    """Under 24x24: either edge below the minimum (axe/WCAG use the smaller-than-minimum test on
    EITHER dimension -- a 200x12 link is undersized)."""
    return rec["w"] < min_px - 0.01 or rec["h"] < min_px - 0.01


def _rect_gap(a: Record, b: Record) -> float:
    """Shortest distance between two rectangles' areas (0 when they touch or overlap)."""
    dx = max(a["x"] - (b["x"] + b["w"]), b["x"] - (a["x"] + a["w"]), 0.0)
    dy = max(a["y"] - (b["y"] + b["h"]), b["y"] - (a["y"] + a["h"]), 0.0)
    return math.hypot(dx, dy)


def effective_size(rec: Record, targets: List[Record], min_px: float = MIN_PX) -> Tuple[float, float]:
    """The tap target's effective (width, height), UNIONING adjacent same-destination links.

    WCAG 2.5.8 treats links that do the same thing as ONE target. The wiki's icon+text pattern
    (`<a href=X><img></a> <a href=X>text</a>`) and a gallery's thumbnail+caption both split one
    destination across two small boxes; a user tapping either lands in the same place, so the real
    target is their union -- which clears 24x24 even when each piece does not. Union only same-href
    links that are ADJACENT (touching/overlapping or within min_px), so two unrelated uses of one
    href elsewhere on the page are never merged into a bogus page-spanning target."""
    x0, y0 = rec["x"], rec["y"]
    x1, y1 = rec["x"] + rec["w"], rec["y"] + rec["h"]
    href = rec.get("href") or ""
    if href:
        for o in targets:
            if o is rec or (o.get("href") or "") != href:
                continue
            if _rect_gap(rec, o) <= min_px:
                x0 = min(x0, o["x"]); y0 = min(y0, o["y"])
                x1 = max(x1, o["x"] + o["w"]); y1 = max(y1, o["y"] + o["h"])
    return x1 - x0, y1 - y0


def well_spaced(rec: Record, others: List[Record], min_px: float = MIN_PX) -> bool:
    """True when `rec`'s 24px-diameter circle (radius min_px/2) intersects NO other target's box
    and NO other undersized target's circle -- the WCAG 2.5.8 spacing exception. An isolated small
    link is well-spaced (passes); a crowded one is not.

    Both halves of the exception:
      - vs another target's BOX: the circle (radius r) must not reach into any other target's rect.
      - vs another UNDERSIZED target's circle (radius r): two radius-r circles intersect when their
        centres are < 2r (== min_px) apart.
    `others` should be every OTHER rendered target on the page (not just candidates), because a
    nearby large button crowds a small link just as a nearby small link does."""
    r = min_px / 2.0
    cx, cy = _center(rec)
    href = rec.get("href") or ""
    for other in others:
        if other is rec:
            continue
        # Two links to the SAME destination are functionally ONE target -- a mis-tap between them
        # lands the user in the same place, which is harmless, so they do not "crowd" each other in
        # the sense 2.5.8 guards (WCAG's equivalent-target reasoning). This is exactly the wiki
        # icon+text pattern (a File/Cd-rom icon link beside its same-href text link) and a gallery
        # thumbnail link above its same-href caption link; neither should flag the other.
        if href and (other.get("href") or "") == href:
            continue
        ocx, ocy = _center(other)
        if is_undersized(other, min_px):
            if math.hypot(cx - ocx, cy - ocy) < min_px:
                return False
        if _circle_hits_rect(cx, cy, r, other):
            return False
    return True


def evaluate(records: List[Record], min_px: float = MIN_PX) -> List[Record]:
    """The verdict for one (page, viewport): every FAILING candidate. Pure -- the whole gate
    decision is unit-tested here with no browser.

    A candidate FAILS WCAG 2.5.8 when ALL hold:
      - it is a candidate we judge (candidate == True),
      - it is NOT inline-exempt (standalone == True),
      - it is undersized (< 24x24), AND
      - it is NOT well-spaced (its 24px circle crowds another target).
    An inline (sentence) link, a large link, and an isolated small standalone link all PASS."""
    targets = [r for r in records if r["w"] > 0 and r["h"] > 0]
    fails: List[Record] = []
    for rec in targets:
        if not rec.get("candidate"):
            continue
        if not rec.get("standalone"):
            continue
        # Size against the EFFECTIVE target (same-href adjacent links unioned): an icon+text or
        # thumbnail+caption pair that together clears 24x24 is one adequately-sized target.
        ew, eh = effective_size(rec, targets, min_px)
        if ew >= min_px - 0.01 and eh >= min_px - 0.01:
            continue
        if well_spaced(rec, targets, min_px):
            continue
        fails.append(rec)
    return fails


# In-page extractor. Returns one record per rendered interactive target; CONTENT links inside a
# text block are flagged `candidate` and classified `standalone` (the block holds no sentence text
# around the link). Everything else (nav/button/control, and links outside a text block) is a
# non-candidate NEIGHBOUR -- measured only so the spacing test sees it. All geometry decisions are
# made in Python from these rectangles; this only reads the DOM.
#
# standalone classification (the WCAG inline exception, inverted): walk up to the nearest text
# block (li/p/dd/dt/td/th/figcaption/dl). The link is INLINE (exempt) when that block holds real
# text OTHER than its link descendants -- a sentence around the link. It is STANDALONE when the
# block's only non-whitespace text comes from links (a link-only list item / cell). A short
# separator between links (one or two punctuation chars like a middot/pipe/comma) does NOT count as
# a sentence, so a row of separated links still reads as standalone.
TAPTARGET_JS = r"""
() => {
  const MIN = 24;
  const BLOCK = new Set(['LI','P','DD','DT','TD','TH','FIGCAPTION','DL']);
  // The CONTENT region only (not page chrome). querySelector on a list returns the first match in
  // TREE order, so '.wiki-content, main, body' would return <body> (outermost) and pull in the
  // header/footer/nav -- a different tap-target surface owned elsewhere. Pick the content root
  // explicitly: main.wiki-content, else main, else .wiki-content, else the body as a last resort.
  const SCOPE = document.querySelector('main.wiki-content') || document.querySelector('main')
             || document.querySelector('.wiki-content') || document.body;
  const rects = [];
  const seen = new Map();
  const shown = (el) => {
    const s = getComputedStyle(el);
    if (s.visibility === 'hidden' || s.display === 'none' || parseFloat(s.opacity) === 0)
      return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const name = (el) => {
    let s = el.tagName.toLowerCase();
    const cls = (el.getAttribute('class') || '').trim();
    if (cls) s += '.' + cls.split(/\s+/)[0];
    return s;
  };
  const push = (el, candidate, standalone) => {
    const r = el.getBoundingClientRect();
    // A compact ancestor chain (nearest 4) so a failure line names the real container -- which
    // CSS selector must grow the tap target (list item, cell paragraph, gallery, ...).
    const chain = [];
    let n = el;
    for (let i = 0; i < 4 && n && n.nodeType === 1; i++) { chain.unshift(name(n)); n = n.parentElement; }
    rects.push({ x: r.x, y: r.y, w: r.width, h: r.height,
                 candidate: candidate, standalone: standalone,
                 sel: chain.join('>'), href: (el.getAttribute('href') || '').slice(0, 120) });
  };
  // Every rendered interactive target -- the spacing neighbour set. document-wide (header nav,
  // buttons) so a small content link crowded by a control is still caught.
  const INTERACTIVE = 'a[href], button, input:not([type=hidden]), select, textarea, '
                    + '[role=button], [tabindex]:not([tabindex="-1"])';
  const interactive = [];
  // Neighbours are drawn from the CONTENT region only. A page-chrome overlay -- the fixed cookie
  // consent banner, a sticky header, the footer -- floats over or sits outside the content flow
  // and is not a persistent neighbour a content link can be mis-tapped against; counting it would
  // flag a content link merely because a dismissible banner happens to overlap it at the viewport
  // bottom. Same scope as the candidates, so only content-vs-content crowding is judged.
  SCOPE.querySelectorAll(INTERACTIVE).forEach((el) => { if (shown(el)) interactive.push(el); });
  // Content-link candidates: a[href] inside the content scope. Classify standalone vs inline.
  // Citation / edit-section markers (a [N] footnote superscript, a cite backlink, an edit link)
  // are INLINE targets by nature -- in a sentence, constrained by its line-height -- so WCAG 2.5.8
  // exempts them; they are never candidates (they REMAIN spacing neighbours via `interactive`).
  // This keeps the lane from fighting the separate footnote-superscript fix, which deliberately
  // makes an in-text [N] a tiny raised mark.
  const EXEMPT_MARKER = 'sup, .reference, .mw-cite-backlink, .mw-editsection, .cite-backlink, '
                      + '.ext-link-to-archive';
  const candidates = new Set();
  SCOPE.querySelectorAll('a[href]').forEach((a) => {
    if (!shown(a)) return;
    if (a.closest(EXEMPT_MARKER)) return;     // inline citation/edit marker -> WCAG-exempt
    // Navigation chrome (site nav + its submenu, the in-page TOC, the book mini-nav) is a
    // DISTINCT tap-target component with its own sizing, not the content prose this lane guards --
    // and it is owned by the header/nav work, not here. Scope to content links.
    if (a.closest('nav, .toc, .mininav, .site-nav, .nav-submenu, .footer-links')) return;
    // TEXT tap targets only. A link with no visible text is an image/icon link (a gallery
    // thumbnail, an info-box notice icon, a 15x15 app-grid glyph); its tap size is governed by
    // the IMAGE's dimensions (the img-dims / responsiveness gates), a different concern than the
    // text-link crowding this lane guards -- and measuring one with a broken/absent image yields a
    // spurious tiny rect. Require real text so this lane stays the text-link gate it is.
    if (!(a.textContent || '').trim()) return;
    let block = a.parentElement;
    while (block && !BLOCK.has(block.tagName)) block = block.parentElement;
    if (!block) return;                       // not in a text block -> let the general lane handle
    // Text of the block that is NOT inside any <a> descendant (the 'sentence' around the link).
    let linkText = '';
    block.querySelectorAll('a').forEach((x) => { linkText += x.textContent; });
    const blockText = block.textContent || '';
    const nonLink = blockText.replace(/\s+/g, '').length - linkText.replace(/\s+/g, '').length;
    // Allow a couple of separator chars (middot / pipe / comma between links) as still standalone.
    const standalone = nonLink <= 2;
    candidates.add(a);
    push(a, true, standalone);
  });
  // Neighbours: interactive targets that are not already pushed as candidates.
  interactive.forEach((el) => { if (!candidates.has(el)) push(el, false, false); });
  return rects;
}
"""


# Eager-load every image and nudge IntersectionObserver-based lazy loaders with a full scroll,
# then return to the top so getBoundingClientRect is measured from the same origin as a fresh load.
_FORCE_LAZY_JS = (
    "() => { try { "
    "for (const img of document.querySelectorAll('img[loading=\"lazy\"]')) img.loading = 'eager'; "
    "window.scrollTo(0, document.body.scrollHeight); window.scrollTo(0, 0); "
    "} catch (e) {} }")


async def _taptarget_page(browser, url: str, width: int, height: int,
                          settle_ms: int) -> Dict[str, Any]:
    """Load one page at one viewport, return its extracted records (or a redirect/status marker).
    Mirrors axe._axe_page's hermetic routing so an off-mount redirect stub is not measured."""
    from urllib.parse import urlparse
    allowed = urlparse(url).netloc
    nav: Dict[str, Any] = {"count": 0, "redirect": None}
    page = await browser.new_page(viewport={"width": width, "height": height})

    async def _hermetic(route):
        req = route.request
        if req.is_navigation_request() and req.frame == page.main_frame:
            nav["count"] += 1
            if nav["count"] == 1:
                await route.continue_()
                return
            nav["redirect"] = req.url
            await route.abort()
            return
        if urlparse(req.url).netloc == allowed:
            await route.continue_()
        else:
            await route.abort()

    await page.route("**/*", _hermetic)
    try:
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=45000)
        except Exception:
            if nav["redirect"]:
                return {"redirect": nav["redirect"]}
            raise
        if nav["redirect"]:
            return {"redirect": nav["redirect"]}
        status = resp.status if resp is not None else 0
        if status < 200 or status >= 400:
            return {"status": status}
        # Force lazy images to load before measuring. The wiki's icon+text link pairs
        # (`<a href=X><img loading=lazy></a> <a href=X>text</a>`) rely on the icon's box to form a
        # >=24px same-href target; a below-the-fold lazy icon stays unloaded (0x0) on a static load,
        # so the pair would FALSELY read as just the narrow text link. A real user sees the icon
        # once the row scrolls in -- so eager-load every image (and nudge any IntersectionObserver
        # loader with a scroll) to measure the real visible state. Mirrors mobile.py forcing
        # content-visibility before an a11y measure.
        await page.evaluate(_FORCE_LAZY_JS)
        await page.wait_for_timeout(settle_ms)
        if nav["redirect"]:
            return {"redirect": nav["redirect"]}
        records = await page.evaluate(TAPTARGET_JS)
        return {"status": status, "records": records}
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=5)
        except Exception:
            # Best-effort teardown: a page that already closed / hangs on close must not mask the
            # measurement or the real exception in flight.
            pass


class _EngineUnavailable(Exception):
    """chromium failed to launch. Caller: env-unmet SKIP(77) only while nothing has been measured;
    a launch failure after a root already ran is a mid-run fault (mirrors axe)."""


async def check(base: str, paths: List[str], settle_ms: int = SETTLE_MS,
                hard_timeout: int = HARD_TIMEOUT) -> Tuple[List[str], List[str]]:
    """Measure every page at every viewport. Returns (failures, problems): a failure is a WCAG
    2.5.8 violation line; a problem is an unauditable page (wedge / bad status), which the caller
    fails on -- an unmeasured page is never a silent clean (mirrors axe.check)."""
    from playwright.async_api import async_playwright

    failures: List[str] = []
    problems: List[str] = []
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as exc:              # noqa: BLE001 -- engine not installed
            raise _EngineUnavailable(str(exc)) from exc
        for path in paths:
            url = base.rstrip("/") + "/" + path.lstrip("/")
            for vname, vw, vh in VIEWPORTS:
                try:
                    res = await asyncio.wait_for(
                        _taptarget_page(browser, url, vw, vh, settle_ms), timeout=hard_timeout)
                except Exception:
                    try:
                        await asyncio.wait_for(browser.close(), timeout=5)
                    except Exception:
                        # The page wedged; a close that also errors/hangs does not change recovery.
                        # Relaunch a clean browser so the wedge cannot cascade to later pages.
                        pass
                    browser = await p.chromium.launch()
                    print("TIMEOUT   %s [%s]" % (path, vname), flush=True)
                    problems.append("wedged: %s [%s]" % (path, vname))
                    continue
                if res.get("redirect"):
                    print("redir     %s [%s]" % (path, vname), flush=True)
                    continue
                status = res.get("status", 0)
                if status < 200 or status >= 400:
                    print("HTTP %-4d %s [%s]" % (status, path, vname), flush=True)
                    problems.append("bad status %d: %s [%s]" % (status, path, vname))
                    continue
                fails = evaluate(res.get("records", []))
                print("%-9s %3d %s [%s]" % ("viol" if fails else "ok", len(fails), path, vname),
                      flush=True)
                for rec in fails:
                    line = ("%s [%s]: %s %.0fx%.0f px -> %s"
                            % (path, vname, rec["sel"], rec["w"], rec["h"],
                               _safe_terminal(rec.get("href", ""))))
                    failures.append(line)
                    print("          -> %s" % _safe_terminal(line), flush=True)
        try:
            await asyncio.wait_for(browser.close(), timeout=5)
        except Exception:
            # Best-effort final teardown: the measurement is complete and captured; a close that
            # errors/hangs here must not turn a clean run into a failure.
            pass
    return failures, problems


def _docroots(roots: List[str]) -> Dict[str, dict]:
    """Group roots into docroots exactly like axe/console/mobile: a top-level site serves itself; a
    subsite mounts under its parent's docroot at its mount path (skipped if the parent is absent)."""
    by_name = {os.path.basename(r): r for r in roots}
    docroots: Dict[str, dict] = {}
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
    return docroots


def _load_paths_file(path: str) -> List[str]:
    """Root-relative audit paths (one per line, blank / '#' skipped) -- a CURATED sample so a huge
    tree (the ~9000-page wikis) is gated on a representative subset, mirroring axe._load_paths_file."""
    out: List[str] = []
    for raw in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def _serve_and_check(docroot: str, entry: dict, settle_ms: int, hard_timeout: int,
                     restrict: Optional[List[str]]) -> Tuple[List[str], List[str]]:
    """Serve one docroot on a localhost mount (reusing mobile.py's harness) and measure its pages.
    `restrict` (a curated path list) overrides the enumerated tree."""
    handler = functools.partial(_MountHandler, directory=docroot)
    httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
    httpd.mounts = entry['mounts']
    port = httpd.server_address[1]
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = 'http://127.0.0.1:%d' % port
        paths = sorted(set(entry['urls'])) if restrict is None else list(restrict)
        return asyncio.run(check(base, paths, settle_ms, hard_timeout))
    finally:
        httpd.shutdown()


def check_roots(roots: List[str], settle_ms: int = SETTLE_MS, hard_timeout: int = HARD_TIMEOUT,
                restrict: Optional[List[str]] = None) -> int:
    """Gate each site root. SKIPs(77) when Playwright/chromium is absent and nothing has run yet; a
    launch failure after a root already ran is a mid-run fault (overall=1), never a silent SKIP."""
    if restrict is not None and not restrict:
        sys.stderr.write("taptarget: empty restriction (no paths) -- refusing a vacuous audit\n")
        return 2
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401  (engine launch is inside check())
    except ImportError:
        _skip('python3-playwright not installed')

    overall = 0
    audited = 0
    for docroot, entry in _docroots(roots).items():
        site = os.path.basename(os.path.normpath(docroot))
        try:
            failures, problems = _serve_and_check(docroot, entry, settle_ms, hard_timeout, restrict)
        except _EngineUnavailable as exc:
            if audited == 0:
                _skip('chromium engine unavailable: %s' % exc)
            print("%s: FAIL    chromium engine became unavailable mid-run: %s" % (site, exc),
                  file=sys.stderr)
            return 1
        audited += 1
        for line in failures:
            print("%s: FAIL    %s" % (site, _safe_terminal(line)), file=sys.stderr)
        for problem in problems:
            print("%s: FAIL    %s" % (site, problem), file=sys.stderr)
        print("%s: %d WCAG-2.5.8 violation(s), %d unauditable page(s) (viewports: %s)"
              % (site, len(failures), len(problems),
                 "+".join(n for n, _, _ in VIEWPORTS)))
        if failures or problems:
            overall = 1
    if audited == 0:
        _skip('no pages served (subsite parents absent?)')
    return overall


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="WCAG 2.5.8 target-size geometric gate (local-serve, mobile+desktop).")
    ap.add_argument("--settle", type=int, default=SETTLE_MS,
                    help="post-load settle time in ms before measuring (default %d)" % SETTLE_MS)
    ap.add_argument("--paths-file", default=None,
                    help="restrict the audit to the root-relative paths in this file (one per "
                         "line, blank/# skipped) -- a curated sample instead of the whole tree")
    ap.add_argument("roots", nargs="+", help="site checkout root(s) with index.html")
    args = ap.parse_args(argv)
    restrict = None
    if args.paths_file:
        restrict = _load_paths_file(args.paths_file)
        if not restrict:
            sys.stderr.write("taptarget: --paths-file '%s' has no paths -- refusing to fall back "
                             "to a full-tree audit (omit the flag for a full audit)\n"
                             % args.paths_file)
            return 2
    return check_roots(args.roots, args.settle, restrict=restrict)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
