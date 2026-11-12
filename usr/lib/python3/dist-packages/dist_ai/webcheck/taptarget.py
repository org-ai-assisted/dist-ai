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

SCOPE / threat model: this is a REGRESSION gate over our OWN generator's trusted static HTML, not
an adversarial WCAG scanner. It catches a realistic size/spacing regression in generated wiki
content; it does NOT try to resist hostile markup crafted to slip past it (the generator, not an
attacker, writes the audited pages). Two consequences worth stating plainly:
  - `standalone` is a BLOCK-TEXT heuristic (does the link's enclosing li/p/td hold non-link
    sentence text), not a line-box analysis. A block-level link that happens to share a block with
    unrelated prose can be mis-classified inline (under-flagged); a real generated page does not mix
    a stacked link list with a sentence in one block, so this has not occurred on the wikis.
  - geometry is judged on the bounding RECTANGLE (what getBoundingClientRect / axe measure); a
    clip-path/rounded target with a smaller solid area, a WebSocket/service-worker exfil from a
    hostile page, and onclick-differing same-href links are all out of scope -- none is produced by
    our generator. The hermetic page routing mirrors webcheck.axe and is defence-in-depth, not an
    exfil boundary (the sandbox confinement is).
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
# Per-(page,viewport) hard wall-clock, s. MUST exceed the inner goto timeout (45s) with headroom
# for the post-nav force-lazy + settle + two evaluates, or a page whose networkidle legitimately
# lands near 45s is cancelled before its (successful) measurement and falsely reported "wedged".
# 55 gives ~10s headroom over the 45s goto, matching axe.check.
HARD_TIMEOUT = 55
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
    for other in others:
        if other is rec:
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
        if not is_undersized(rec, min_px):
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
  // Visibility filter: the element's OWN visibility:hidden / display:none / opacity:0, then a
  // nonzero box. Deliberately NOT an ancestor-opacity walk: opacity does not disable hit-testing,
  // so an opacity:0 ANCESTOR still leaves its descendants as live pointer targets (and a
  // display:contents or top-layer box is painted outside that ancestor's opacity entirely) --
  // excluding them would DROP real crowding neighbours (false negative). Our generator hides an
  // inactive panel with display:none / visibility:hidden (both caught here), never bare opacity:0.
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
  const INTERACTIVE = 'a[href], button, input:not([type=hidden]), select, textarea, summary, '
                    + '[role=button], [tabindex]:not([tabindex="-1"])';
  const interactive = [];
  // Neighbours are drawn from the CONTENT region only. A page-chrome overlay -- the fixed cookie
  // consent banner, a sticky header, the footer -- floats over or sits outside the content flow
  // and is not a persistent neighbour a content link can be mis-tapped against; counting it would
  // flag a content link merely because a dismissible banner happens to overlap it at the viewport
  // bottom. Same scope as the candidates, so only content-vs-content crowding is judged.
  // An inline citation/archive marker (the [N] superscript, the "archived version" icon) is a tiny
  // raised mark, not a tap-target competing for the same tap, so it is excluded from the neighbour
  // set as well as from candidacy -- else a content link sitting beside its own citation marker
  // (a comparison-table header link next to its archive icon) reads as crowded though it is not.
  const EXEMPT_MARKER = 'sup, .reference, .mw-cite-backlink, .mw-editsection, .cite-backlink, '
                      + '.ext-link-to-archive';
  SCOPE.querySelectorAll(INTERACTIVE).forEach((el) => {
    if (shown(el) && !el.closest(EXEMPT_MARKER)) interactive.push(el);
  });
  // Content-link candidates: a[href] inside the content scope. Classify standalone vs inline.
  // Citation / edit-section markers (a [N] footnote superscript, a cite backlink, an edit link)
  // are INLINE targets by nature -- in a sentence, constrained by its line-height -- so WCAG 2.5.8
  // exempts them; they are never candidates (they REMAIN spacing neighbours via `interactive`).
  // This keeps the lane from fighting the separate footnote-superscript fix, which deliberately
  // makes an in-text [N] a tiny raised mark. (EXEMPT_MARKER is defined above, where the same
  // markers are also excluded from the neighbour set.)
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
    if (!(a.innerText || '').trim()) return;
    let block = a.parentElement;
    while (block && !BLOCK.has(block.tagName)) block = block.parentElement;
    if (!block) return;                       // not in a text block -> let the general lane handle
    // RENDERED non-link text of the block (the 'sentence' around the link). Both sides MUST use the
    // same rendered basis: block.innerText (not textContent) already EXCLUDES a display:none /
    // visually-hidden descendant, a <script>/<style>, etc. x.innerText tracks that rendered basis in
    // every case EXCEPT one: on an element inside a display:none subtree it falls back to the RAW
    // descendant text content, so summing every anchor's innerText would subtract text blockText
    // never counted -- driving nonLink negative and wrongly marking an in-sentence link standalone
    // (two crowded inline links then read as false violations). So subtract an anchor only when it is
    // actually RENDERED in the block: not inside a display:none subtree up to the block. The test is
    // display-only (NOT a box/getClientRects test) on purpose -- a display:contents anchor has NO box
    // yet its text IS in block.innerText, and visibility:hidden / opacity:0 already yield the right
    // x.innerText ('' / the rendered text); getClientRects or shown() would wrongly drop those
    // rendered contributions, over-counting nonLink and FALSELY exempting a real standalone link.
    // (This is a block-text heuristic, not a line-box analysis -- see the module docstring.)
    const renderedInBlock = (x) => {
      for (let el = x; el && el !== block; el = el.parentElement) {
        if (getComputedStyle(el).display === 'none') return false;
      }
      return true;
    };
    let linkText = '';
    block.querySelectorAll('a').forEach((x) => {
      if (renderedInBlock(x)) linkText += (x.innerText || '');
    });
    const blockText = block.innerText || '';
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
                hard_timeout: int = HARD_TIMEOUT) -> Tuple[List[str], List[str], int]:
    """Measure every page at every viewport. Returns (failures, problems, measured): a failure is a
    WCAG 2.5.8 violation line; a problem is an unauditable page (wedge / bad status), which the
    caller fails on -- an unmeasured page is never a silent clean (mirrors axe.check). `measured` is
    the count of (page, viewport) loads actually audited (not a redirect stub / bad status / wedge),
    so the caller can refuse a vacuous audit where nothing was measured."""
    from playwright.async_api import async_playwright

    failures: List[str] = []
    problems: List[str] = []
    measured = 0
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
                    print("TIMEOUT   %s [%s]" % (_safe_terminal(path), vname), flush=True)
                    problems.append("wedged: %s [%s]" % (path, vname))
                    continue
                if res.get("redirect"):
                    print("redir     %s [%s]" % (_safe_terminal(path), vname), flush=True)
                    continue
                status = res.get("status", 0)
                if status < 200 or status >= 400:
                    print("HTTP %-4d %s [%s]" % (status, _safe_terminal(path), vname), flush=True)
                    problems.append("bad status %d: %s [%s]" % (status, path, vname))
                    continue
                measured += 1
                fails = evaluate(res.get("records", []))
                print("%-9s %3d %s [%s]" % ("viol" if fails else "ok", len(fails), _safe_terminal(path), vname),
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
    return failures, problems, measured


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
                     restrict: Optional[List[str]]) -> Tuple[List[str], List[str], int]:
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
            failures, problems, measured = _serve_and_check(docroot, entry, settle_ms,
                                                             hard_timeout, restrict)
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
        # Vacuous-audit guard (fail CLOSED, mirrors axe._VacuousAudit): a docroot that was served
        # but measured ZERO pages -- every requested page was a redirect stub -- certifies nothing,
        # so a "0 violations" is a hollow pass. This lane has no baseline to backstop it, so refuse
        # it here. Only fires when there were no real failures/problems (those already red the gate).
        if measured == 0 and not failures and not problems:
            print("%s: FAIL    vacuous audit -- every served page redirected, 0 tap targets measured"
                  % site, file=sys.stderr)
            overall = 1
        print("%s: %d WCAG-2.5.8 violation(s), %d unauditable page(s), %d page-view(s) measured"
              " (viewports: %s)"
              % (site, len(failures), len(problems), measured,
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
