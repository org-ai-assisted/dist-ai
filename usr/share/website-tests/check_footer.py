#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Footer row-alignment guard for the GitHub Pages sites.

The static suite (check_site.py) cannot SEE the resolved cascade, so it missed a
footer whose rows do not share the same horizontal gutter -- the freedom-badges
row `<div class="wrap ffree">` sat ~20px left of every other footer row because
its own `padding:14px 0 2px` shorthand zeroed the horizontal gutter that the
sibling rows (.ftop/.fbot) re-add, and no equivalent re-add existed for it. The
result is one footer row visibly out of line with the rest ("footer looks broken
spacing"), invisible to a token/markup check.

This guard renders every page in a real browser and measures, per DIRECT child
row of <footer>, the content-box left and right insets. Every laid-out row must
share the same insets (within TOL px); a row that does not is flagged. Measured
at a desktop AND a phone width, because the gutter is re-tuned at <=640px and the
bug reproduced at both.

Like check_mobile.py / check_width.py this needs a real browser (Playwright +
chromium) and shares that module's page discovery and HTTP mount harness. It
SKIPs (exit 77) cleanly when the browser is unavailable, so the static suite
still runs everywhere; where a browser IS present (CI, the sandbox) it gates the
layout.

Usage: check_footer.py <site-root> [<site-root> ...]
"""

import functools
import os
import statistics
import sys
from typing import Any

# Share the proven discovery + HTTP mount harness (no browser at import time).
from check_mobile import _MountHandler, _MountingTCPServer, _page_urls, _skip, SUBSITES

# Widths the footer alignment is judged at: a representative desktop (rows sit in
# the centered wrap) and a phone (<=640px, where the gutter is re-tuned and the
# rows may re-flow to a column). The bug reproduced at both.
FOOTER_WIDTHS = (1440, 390)
VIEWPORT_HEIGHT = 1000

# Max px a row's content-box inset may deviate from the footer's median inset.
# The real defect is ~20px; 2px absorbs sub-pixel layout rounding.
TOL = 2

# Per-row content-box inset measurement. For each DIRECT child of <footer> that
# is actually laid out (skip <script>, display:none, and zero-size rows), the
# left/right edge of its CONTENT box (border + padding removed), plus a short
# name (id or first class token) for the failure message. Comparing the content
# box -- not the border box -- is what catches a row that keeps the same centered
# width but zeroes its own gutter.
_MEASURE_JS = r"""
() => {
  const footer = document.querySelector('footer');
  if (!footer) return null;
  const out = [];
  for (const row of footer.children) {
    if (row.tagName === 'SCRIPT' || row.tagName === 'STYLE') continue;
    const s = getComputedStyle(row);
    if (s.display === 'none' || s.visibility === 'hidden') continue;
    const r = row.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    const padL = parseFloat(s.paddingLeft) || 0;
    const padR = parseFloat(s.paddingRight) || 0;
    const bL = parseFloat(s.borderLeftWidth) || 0;
    const bR = parseFloat(s.borderRightWidth) || 0;
    out.push({
      name: row.id ? ('#' + row.id)
                   : (row.className ? '.' + String(row.className).trim().split(/\s+/).join('.')
                                    : row.tagName.toLowerCase()),
      left: Math.round(r.left + bL + padL),
      right: Math.round(r.right - bR - padR),
    });
  }
  return out;
}
"""


def misaligned_rows(rows, tol=TOL):
    """Rows whose content-box left OR right inset deviates from the footer's
    median inset by more than `tol` px. Pure Python over the measured row dicts,
    so it is unit-testable without a browser. Fewer than two rows -> nothing to
    compare -> no offenders."""
    if len(rows) < 2:
        return []
    med_left = statistics.median(r['left'] for r in rows)
    med_right = statistics.median(r['right'] for r in rows)
    out = []
    for r in rows:
        dl = abs(r['left'] - med_left)
        dr = abs(r['right'] - med_right)
        if dl > tol or dr > tol:
            out.append({'name': r['name'], 'left': r['left'], 'right': r['right'],
                        'med_left': med_left, 'med_right': med_right,
                        'axis': 'left' if dl > tol else 'right'})
    return out


def _docroots(roots):
    """Group site roots into HTTP docroots, mounting any subsite under its parent
    (mirrors check_mobile.main). Returns {docroot: {'mounts': {...}, 'urls': [...]}}."""
    by_name = {os.path.basename(r): r for r in roots}
    docroots: dict[str, dict[str, Any]] = {}
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
            httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
            httpd.mounts = entry['mounts']
            port = httpd.server_address[1]
            httpd.daemon_threads = True
            import threading
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                for url in sorted(set(entry['urls'])):
                    checked += 1
                    for width in FOOTER_WIDTHS:
                        page = browser.new_page(
                            viewport={'width': width, 'height': VIEWPORT_HEIGHT})
                        try:
                            resp = page.goto('http://127.0.0.1:%d%s' % (port, url))
                            if resp is not None and resp.status >= 400:
                                failures += 1
                                sys.stderr.write('FAIL %s: served %d (not a real page)\n'
                                                 % (url, resp.status))
                                continue
                            page.wait_for_timeout(350)
                            rows = page.evaluate(_MEASURE_JS)
                            if not rows:
                                continue          # no footer on this page
                            for off in misaligned_rows(rows):
                                failures += 1
                                sys.stderr.write(
                                    'FAIL %s @%dpx: footer row %s content-%s %dpx vs '
                                    'median %dpx -- footer rows must share the same '
                                    'horizontal gutter (add the missing padding-left/'
                                    'right re-add for this row)\n'
                                    % (url, width, off['name'], off['axis'],
                                       off[off['axis']],
                                       off['med_' + off['axis']]))
                        finally:
                            page.close()
            finally:
                httpd.shutdown()
                httpd.server_close()
        browser.close()

    if checked == 0:
        _skip('no pages served (subsite parents absent?)')
    if failures:
        sys.stdout.write('website-footer-tests: %d misaligned footer row(s) across %d pages\n'
                         % (failures, checked))
        return 1
    sys.stdout.write('website-footer-tests: %d pages clean -- every footer row shares '
                     'the same gutter at %s\n'
                     % (checked, '/'.join('%dpx' % w for w in FOOTER_WIDTHS)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
