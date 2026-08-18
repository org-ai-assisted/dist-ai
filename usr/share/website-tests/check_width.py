#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Desktop width-utilization guard ("the virtual ruler") for the GitHub Pages sites.

The static suite (check_site.py) has a heuristic that flags a <section> stacking
2+ prose-only .issue cards full-width; it cannot SEE the rendered layout, so it
misses a single narrow column, a non-.issue list (a stacked FAQ), or a section
whose reading column simply sits at a third of the width with a wide empty gutter
-- the "it only uses ~33% of the space" bug. This guard renders every page at a
desktop viewport and measures, per top-level <section>, the CONTENT EXTENT: the
horizontal span actually covered by the section's content (the union of its text
blocks AND its form controls / media). A multi-column grid spans the full wrap; a
single narrow column does not. A section is an OFFENDER when its content extent
covers less than MIN_UTIL of its container AND it holds no genuinely-wide element
(a table / figure / code block that legitimately fills the width) AND it is tall
and text-heavy (a one-line lead with a gutter is not the bug).

Like check_mobile.py this needs a real browser (Playwright + chromium) and shares
that module's page discovery and HTTP mount harness. It SKIPs (exit 77) cleanly
when the browser is unavailable, so the static suite still runs everywhere; where
a browser IS present (CI, the sandbox) it gates the layout.

Usage: check_width.py <site-root> [<site-root> ...]
"""

import functools
import os
import socketserver
import sys

# Share the proven discovery + HTTP mount harness (no browser at import time).
from check_mobile import _MountHandler, _page_urls, _skip, SUBSITES

# Desktop viewport the utilization is judged at. At >= the sites' wrap max-width
# (1000-1080px) the content is already at its cap, so utilization vs the wrap is
# stable above this; 1440 is a representative desktop.
DESKTOP_WIDTH = 1440
VIEWPORT_HEIGHT = 1000

# An offender's content extent covers less than this fraction of its wrap.
MIN_UTIL = 0.80
# A section holding an element at least this wide (table/figure/pre/media) fills
# the width legitimately -- a narrow prose column beside it is not wasted space.
WIDE_EXEMPT = 0.85
# Only tall, text-heavy sections count: a short lead paragraph with a gutter is
# readable typography, not the bug the ruler exists to catch.
MIN_SECTION_PX = 320
MIN_CHARS = 500

# Per-section content-extent measurement. For each top-level <section>: its
# container (a direct-child .wrap, else the section), the available inner width
# (clientWidth minus padding), the union horizontal span of every content unit
# inside it (elements owning >= 40 chars of direct text, plus form controls and
# media), and the widest genuinely-wide element present.
#
# Denominator = the page's STANDARD content column, i.e. the widest .wrap on the
# page, not each section's own container. Measuring against the section's own
# wrap would let a section that narrows its OWN wrap to a third of the page pass
# at ~1.0 (its content fills that narrow wrap) -- the very layout the gate must
# reject. A section with no .wrap is judged against its own width (self-relative).
#
# Section weight (MIN_CHARS) counts the section's FULL rendered text, not only the
# text in blocks with >= 40 direct chars: a tall FAQ split into many short items
# would otherwise sum to near zero and slip through.
_MEASURE_JS = r"""
() => {
  const WIDE_TAGS = new Set(['TABLE','PRE','FIGURE','IMG','SVG','CANVAS','VIDEO','IFRAME']);
  const FILL_TAGS = new Set(['TEXTAREA','INPUT','SELECT','BUTTON','IMG','SVG',
                             'CANVAS','VIDEO','IFRAME','PRE','TABLE']);
  const directText = (el) => {
    let n = 0;
    for (const c of el.childNodes) if (c.nodeType === 3) n += c.textContent.trim().length;
    return n;
  };
  const innerW = (el) => {
    const cs = getComputedStyle(el);
    return el.clientWidth - (parseFloat(cs.paddingLeft) || 0) - (parseFloat(cs.paddingRight) || 0);
  };
  // the page's standard reading column: the widest .wrap present
  let pageWrap = 0;
  document.querySelectorAll('.wrap').forEach((w) => {
    const iw = innerW(w);
    if (iw > pageWrap) pageWrap = iw;
  });
  const out = [];
  document.querySelectorAll('main > section, body > section').forEach((sec) => {
    const ownWrap = sec.querySelector(':scope > .wrap');
    const wrap = ownWrap || sec;
    // judge against the full column this section COULD use (the page-standard
    // wrap) when it uses a wrap; against its own width otherwise
    const avail = ownWrap ? (pageWrap || innerW(wrap)) : innerW(wrap);
    if (avail < 1) return;
    let wideW = 0, extMinL = Infinity, extMaxR = -Infinity;
    wrap.querySelectorAll('*').forEach((e) => {
      const s = getComputedStyle(e);
      if (s.visibility === 'hidden' || s.display === 'none') return;
      const r = e.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return;
      if (directText(e) >= 40) {
        if (r.left < extMinL) extMinL = r.left;
        if (r.right > extMaxR) extMaxR = r.right;
      }
      if (FILL_TAGS.has(e.tagName) && r.width >= 40) {
        if (r.left < extMinL) extMinL = r.left;
        if (r.right > extMaxR) extMaxR = r.right;
      }
      if (WIDE_TAGS.has(e.tagName) && r.width > wideW) wideW = r.width;
    });
    const extentW = (extMaxR > extMinL) ? (extMaxR - extMinL) : 0;
    const totalChars = (sec.textContent || '').replace(/\s+/g, ' ').trim().length;
    out.push({
      id: sec.id || '',
      cls: String(sec.className || '').slice(0, 40),
      avail: Math.round(avail),
      extUtil: avail ? Math.round(extentW / avail * 1000) / 1000 : 0,
      wideUtil: avail ? Math.round(wideW / avail * 1000) / 1000 : 0,
      totalChars: totalChars,
      secH: Math.round(sec.getBoundingClientRect().height),
      sample: (sec.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 60),
    });
  });
  return out;
}
"""


def is_offender(s):
    """A tall, text-heavy section whose content covers < MIN_UTIL of its wrap and
    that has no genuinely-wide element filling the width. Pure Python over a
    measured section dict, so it is unit-testable without a browser."""
    return (s['extUtil'] < MIN_UTIL
            and s['wideUtil'] < WIDE_EXEMPT
            and s['secH'] >= MIN_SECTION_PX
            and s['totalChars'] >= MIN_CHARS)


def _docroots(roots):
    """Group site roots into HTTP docroots, mounting any subsite under its parent
    (mirrors check_mobile.main). Returns {docroot: {'mounts': {...}, 'urls': [...]}}."""
    by_name = {os.path.basename(r): r for r in roots}
    docroots = {}
    for root in roots:
        sub = SUBSITES.get(os.path.basename(root))
        if sub:
            parent = by_name.get(sub[0])
            if not parent:
                continue
            entry = docroots.setdefault(parent, {'mounts': {}, 'urls': []})
            entry['mounts'][sub[1]] = root
            entry['urls'] += _page_urls(root, sub[1])
        else:
            entry = docroots.setdefault(root, {'mounts': {}, 'urls': []})
            entry['urls'] += _page_urls(root, '')
    return docroots


def main():
    roots = [os.path.abspath(r) for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _skip('python3-playwright not installed')

    docroots = _docroots(roots)
    failures = 0
    checked = 0
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:                 # noqa: BLE001 -- engine not installed
            _skip('chromium engine unavailable: %s' % exc)
        for docroot, entry in docroots.items():
            handler = functools.partial(_MountHandler, directory=docroot)
            httpd = socketserver.TCPServer(('127.0.0.1', 0), handler)
            httpd.mounts = entry['mounts']
            port = httpd.server_address[1]
            httpd.daemon_threads = True
            import threading
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                for url in sorted(set(entry['urls'])):
                    checked += 1
                    page = browser.new_page(
                        viewport={'width': DESKTOP_WIDTH, 'height': VIEWPORT_HEIGHT})
                    try:
                        resp = page.goto('http://127.0.0.1:%d%s' % (port, url))
                        if resp is not None and resp.status >= 400:
                            failures += 1
                            sys.stderr.write('FAIL %s: served %d (not a real page)\n'
                                             % (url, resp.status))
                            continue
                        page.wait_for_timeout(350)
                        for s in page.evaluate(_MEASURE_JS):
                            if is_offender(s):
                                failures += 1
                                ident = ('#' + s['id']) if s['id'] else \
                                    ('.' + s['cls'].split(' ')[0] if s['cls'] else '?')
                                sys.stderr.write(
                                    'FAIL %s: section %s uses %d%% of its width at '
                                    '%dpx (need >=%d%%; no wide element) -- widen the '
                                    'reading measure or lay it out in columns. %r\n'
                                    % (url, ident, round(s['extUtil'] * 100), DESKTOP_WIDTH,
                                       round(MIN_UTIL * 100), s['sample']))
                    finally:
                        page.close()
            finally:
                httpd.shutdown()
                httpd.server_close()
        browser.close()

    if checked == 0:
        _skip('no pages served (subsite parents absent?)')
    if failures:
        sys.stdout.write('website-width-tests: %d underused section(s) across %d pages\n'
                         % (failures, checked))
        return 1
    sys.stdout.write('website-width-tests: %d pages clean -- every tall text section '
                     'uses >=%d%% of its width at %dpx\n'
                     % (checked, round(MIN_UTIL * 100), DESKTOP_WIDTH))
    return 0


if __name__ == '__main__':
    sys.exit(main())
