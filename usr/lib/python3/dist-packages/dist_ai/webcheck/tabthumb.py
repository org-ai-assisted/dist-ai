#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Rendered-layout guard: a wiki tab's PREVIEW THUMBNAIL must be CENTERED on a
phone.

A wiki tab (.tab-content-controller > .tcc-content > .tcc-section) can hold a
preview thumbnail (.thumb with an <img>). On a phone that image should be
centered in the tab body. When a tab body is wrapped in {{GoogleOff}} ->
<div data-nosnippet>, the thumb sits one level deeper and a direct-child CSS rule
missed it, so the image aligned LEFT with a lopsided gap and extra top whitespace
(the CLI tab of /wiki/VirtualBox). This is the rendered regression guard.

Measurement, at the phone width (default 390px), for each
.tab-content-controller, for each :scope > .tcc-content > .tcc-section that holds
a .thumb with an <img>:
  - isolate-activate the section (remove .active from its siblings, add .active to
    it -- the CSS `.mininav-ready .tcc-section:not(.active){display:none}` hides
    the others), so only this section is laid out;
  - measure the IMG box vs the enclosing .tcc-content CONTENT box (subtract the
    pane's padding + client border): leftGap = img.left - contentLeft,
    rightGap = contentRight - img.right;
  - the asymmetry asym = |leftGap - rightGap|. An OFFENDER is asym > ASYM_MAX_PX.
Measure the IMG, not the .thumb wrapper (the wrapper can be full-width while the
image sits left). The controller's original active state is restored afterwards.

This needs a real browser (Playwright), so, like check_mobile.py, it is NOT
pure/static: it SKIPs (exit 77) cleanly when Playwright or chromium is
unavailable, exits 1 when any thumb is off-center, exit 0 when clean. The site is
reached over `--base` (an already-served origin) rather than served from a local
tree, because `.tab-content-controller` is a wiki construct -- the family Pages
sites carry none, so the validated subject is a served wiki stage.

Usage: check_tabthumb.py --base <origin> --path /wiki/Foo [--path ...]
       check_tabthumb.py --base <origin> --paths /wiki/Foo /wiki/Bar
"""

import argparse
import sys
from typing import NoReturn

# Navigation timeout: a content-heavy wiki page on a remote stage can brush the
# Playwright default (30s) under contention; 60s absorbs that without masking a
# genuine hang. Mirrors check_mobile.py.
NAV_TIMEOUT_MS = 60000
# Primary phone width (the validated prototype measured at 390px).
VIEWPORT = 390
# An OFFENDER is a thumb whose left/right gap asymmetry exceeds this many px. The
# fix centers the image (asym ~0); the pre-fix left-aligned CLI thumb measured
# asym ~106, so 12px is a wide, noise-tolerant offender threshold.
ASYM_MAX_PX = 12

# Tab-preview thumbnail CENTERING probe. For each .tab-content-controller, for
# each :scope > .tcc-content > .tcc-section that holds a .thumb > img, isolate-
# activate the section, then measure the IMG box vs the .tcc-content CONTENT box
# (padding + client border subtracted). Returns EVERY such thumb
# {ctrl, sec, name, leftGap, rightGap, asym}; the caller flags asym > ASYM_MAX_PX.
# Restores each controller's original active state afterwards.
#
# Exported as a module constant so the mw-static-generator wiki runner can VENDOR
# it byte-identical: that gate runs under playwright-run's confined venv, which by
# design cannot import dist_ai. A drift guard (test_check_tab_thumb_centering.py)
# FAILS the instant the vendored copy diverges from this one, forcing a conscious
# re-sync -- so the two gates cannot silently drift. Edit the JS HERE, re-sync there.
TABTHUMB_JS = r"""
() => {
  const out = [];
  document.querySelectorAll('.tab-content-controller').forEach((ctrl, ci) => {
    const secs = Array.from(ctrl.querySelectorAll(':scope > .tcc-content > .tcc-section'));
    if (!secs.length) return;
    const origActive = secs.map(s => s.classList.contains('active'));
    secs.forEach((sec, si) => {
      const thumb = sec.querySelector('.thumb');
      if (!thumb) return;
      const img = thumb.querySelector('img');
      if (!img) return;
      secs.forEach(s => s.classList.remove('active'));
      sec.classList.add('active');
      const pane = thumb.closest('.tcc-content');
      const pcs = getComputedStyle(pane);
      const pr = pane.getBoundingClientRect();
      const contentL = pr.left + pane.clientLeft + parseFloat(pcs.paddingLeft);
      const contentR = pr.right - pane.clientLeft - parseFloat(pcs.paddingRight);
      const tb = img.getBoundingClientRect();
      const leftGap = tb.left - contentL, rightGap = contentR - tb.right;
      const name = (img.getAttribute('src') || '').split('/').pop().split('?')[0];
      out.push({ctrl: ci, sec: si, name, leftGap: Math.round(leftGap),
                rightGap: Math.round(rightGap), asym: Math.round(Math.abs(leftGap - rightGap))});
    });
    secs.forEach((s, i) => s.classList.toggle('active', origActive[i]));
  });
  return out;
}
"""


def _skip(msg: str) -> NoReturn:
    sys.stderr.write('website-tabthumb-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


def page_url(base: str, path: str) -> str:
    """Join the base origin and a page path, tolerating a path given without its
    leading slash (e.g. `--path wiki/VirtualBox`): a bare `base + path` would yield
    `http://hostwiki/...`, which Playwright cannot load -- the page would be
    mis-reported rather than measured. Idempotent for an already-rooted path."""
    return base.rstrip('/') + '/' + path.lstrip('/')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', required=True,
                    help='served site origin, e.g. https://kicksecure-stage.github.io')
    ap.add_argument('--width', type=int, default=VIEWPORT,
                    help='viewport width in px (default %d)' % VIEWPORT)
    # --path (repeatable) and --paths (a list) both feed the same page set; at
    # least one is required. A focused check wants explicit pages, not a full
    # tree sweep (tabs live on a handful of wiki pages).
    ap.add_argument('--path', action='append', default=[], metavar='PATH',
                    help='a page path to check; repeat for several')
    ap.add_argument('--paths', nargs='*', default=[], metavar='PATH',
                    help='several page paths to check')
    return ap


def _paths_from(args) -> list:
    """The combined, de-duplicated page list from --path + --paths (order kept)."""
    seen, out = set(), []
    for path in list(args.path) + list(args.paths):
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def main() -> int:
    args = build_parser().parse_args()
    paths = _paths_from(args)
    if not paths:
        build_parser().error('no pages to check (pass --path / --paths)')

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _skip('python3-playwright not installed')

    offenders = 0
    checked = 0
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:                 # noqa: BLE001 -- engine not installed
            _skip('no chromium engine available: %s' % exc)
        try:
            for path in paths:
                url = page_url(args.base, path)
                page = browser.new_page(viewport={'width': args.width, 'height': 844})
                try:
                    resp = page.goto(url, timeout=NAV_TIMEOUT_MS)
                    if resp is not None and resp.status >= 400:
                        offenders += 1
                        sys.stderr.write('FAIL %s: served %d (not a real page)\n'
                                         % (path, resp.status))
                        continue
                    page.wait_for_timeout(400)
                    checked += 1
                    for t in page.evaluate(TABTHUMB_JS):
                        if t['asym'] > ASYM_MAX_PX:
                            offenders += 1
                            sys.stderr.write(
                                'FAIL %s: tab thumb not centered: ctrl %d sec %d %r '
                                'leftGap=%d rightGap=%d asym=%d (budget %d)\n'
                                % (path, t['ctrl'], t['sec'], t['name'],
                                   t['leftGap'], t['rightGap'], t['asym'], ASYM_MAX_PX))
                finally:
                    page.close()
        finally:
            browser.close()

    if offenders:
        sys.stdout.write('website-tabthumb-tests: %d off-center thumb(s) across %d pages\n'
                         % (offenders, checked))
        return 1
    sys.stdout.write('website-tabthumb-tests: %d pages clean at %dpx -- every tab preview '
                     'thumbnail centered (asym <= %dpx)\n' % (checked, args.width, ASYM_MAX_PX))
    return 0


if __name__ == '__main__':
    sys.exit(main())
