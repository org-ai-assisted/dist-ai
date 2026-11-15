#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Rendered-layout guard: a wiki {{LeftRightImageText}} promo row must stay
symmetrical on DESKTOP and must not overlap its text on MOBILE.

A promo row is `div.left-right-image-text[.image-right]` with a `.image`
(the picture column) and a `.text` (heading + copy). The alternating
image-left / image-right rows must MIRROR each other, and on a phone the row
collapses to a single column where the image must sit fully ABOVE the text.
Two real regressions this catches:
  - DESKTOP: the image floats above its heading (dead space under the picture,
    or the heading starts below the image top) -- the mirror metrics alone
    cannot see the vertical misalignment, so textTopGap / imgDeadFoot do.
  - MOBILE: once stacked, flex-wrap/flex-basis left the image box collapsed so
    the picture overlapped the text below it (the reported "image overlaps
    text on mobile").

Measurement (the IMAGE_TEXT_ROW_JS probe), for each `.left-right-image-text`:
  - DESKTOP (1350px): per-metric median + worst per-row deviation across
    imgWidth / nearInset / gap / textFarInset, PLUS the image-left vs
    image-right group-mean mirror delta; PLUS the fixed-target-0 alignment
    metrics textTopGap (heading top vs image-box top) and imgDeadFoot (image-box
    foot vs <img> foot). An OFFENDER is worst > SYM_MAX_PX, or a page missing the
    image-left AND image-right pair (that pair is the whole point of the check).
  - MOBILE (412px, DPR 1.75): overlap = deepest image foot - text top per row
    (>0 means the image intrudes into the text); allStacked confirms every row
    collapsed to one column (imgWidthFrac ~1). An OFFENDER is overlap > SYM_MAX_PX
    or a row that did not stack.

This needs a real browser (Playwright), so, like check_mobile.py / tabthumb.py,
it is NOT pure/static: it SKIPs (exit 77) cleanly when Playwright or chromium is
unavailable, exits 1 when any row offends at either viewport, exit 0 when clean.
The site is reached over `--base` (an already-served origin): the promo rows are a
wiki construct, so the validated subject is a served wiki stage, not a local tree.

IMAGE_TEXT_ROW_JS is exported as a module constant so the mw-static-generator wiki
ruler can VENDOR it byte-identical: that gate runs under playwright-run's confined
venv, which by design cannot import dist_ai. A drift guard (the ruler's
test_check_image_text_row.py) FAILS the instant the vendored copy diverges from
this one, forcing a conscious re-sync so the two gates never silently drift. Edit
the measurement HERE; the ruler adds only its annotation overlay on top.

Usage: check_image_text_row.py --base <origin> --path /wiki/Foo [--path ...]
       check_image_text_row.py --base <origin> --paths / /wiki/Foo
"""

import argparse
import sys
from typing import NoReturn

# Navigation timeout: a content-heavy wiki page on a remote stage can brush the
# Playwright default (30s) under contention; 60s absorbs that without masking a
# genuine hang. Mirrors check_mobile.py / tabthumb.py.
NAV_TIMEOUT_MS = 60000
# Desktop width the mirror symmetry is validated at.
DESKTOP_WIDTH = 1350
# Phone viewport + device scale ratio the mobile stacking is validated at (a common
# Android logical width; the real defect reproduced here).
MOBILE_VIEWPORT = 412
MOBILE_DSR = 1.75
# Offender budget (px), both viewports: a symmetry/alignment deviation this large is a
# real break (mirrored rows measure ~0 delta; clean stacking gives a large NEGATIVE
# overlap, a defect many px positive). Noise-tolerant without masking a regression.
SYM_MAX_PX = 2.0

# Measure the image-text rows and return the numbers + per-row geometry. SINGLE
# self-contained JS (no repo import) so the confined ruler venv can vendor it verbatim.
# Pure measurement: it adds no node, so it never perturbs the layout it reports; the
# ruler draws its canvas overlay in a SEPARATE pass from the geometry returned here.
IMAGE_TEXT_ROW_JS = r"""
(arg) => {
  const tol = arg.tol;
  const mode = arg.mode || 'desktop';     // 'desktop' = mirror symmetry; 'mobile' = stacking overlap
  const rows = Array.from(document.querySelectorAll('.left-right-image-text'));
  const round = (x) => Math.round(x * 100) / 100;
  const measured = [];
  rows.forEach((row, i) => {
    const image = row.querySelector(':scope > .image');
    const text = row.querySelector(':scope > .text');
    if (!image || !text) return;
    const rr = row.getBoundingClientRect();
    const ir = image.getBoundingClientRect();
    const tr = text.getBoundingClientRect();
    const isRight = row.classList.contains('image-right');
    // vertical alignment of the image against the text column:
    //   textTopGap  = text first-child top - image-box top  (want ~0: the text column's first
    //                 rendered element -- the heading on an image-text row -- starts flush with the image
    //                 top). Measured on the SAME element the fix targets (.text > :first-child), so
    //                 the metric and the margin-zeroing rule cannot disagree (a first-heading
    //                 DESCENDANT could be a different node than :first-child, e.g. behind a
    //                 .mw-heading wrapper or intro prose -> a spurious gap).
    //   imgDeadFoot = image-box bottom - <img> bottom (want ~0: no dead space under the image, i.e.
    //                 the pandoc-inserted <p> wrapper's margin does not pad the box below the
    //                 picture). The real generated .image is <div class="image"><p><a><img></a></p>
    //                 </div> (pandoc wraps the bare image), confirmed on the built + live tree.
    const img = image.querySelector('img');
    const first = text.firstElementChild;
    const imr = img ? img.getBoundingClientRect() : ir;
    const hr = first ? first.getBoundingClientRect() : tr;
    const textTopGap = hr.top - ir.top;
    const imgDeadFoot = ir.bottom - imr.bottom;
    // MOBILE (stacked column): the image box and text box must stack cleanly -- the DEEPEST image
    // pixel (lower of the .image box foot and the <img> element foot, since the picture can overflow
    // its box) must sit ABOVE the text top. overlap = deepestImageFoot - text.top: >0 means the
    // image intrudes into the text (the reported "image overlaps text"); <=0 is a clean stack with
    // |overlap| of vertical gap. imgWidthFrac confirms the row actually collapsed to one column
    // (~1.0 stacked; ~0.48 still side-by-side).
    const deepImgFoot = Math.max(ir.bottom, imr.bottom);
    const overlap = deepImgFoot - tr.top;
    const imgWidthFrac = rr.width ? ir.width / rr.width : 0;
    let nearInset, gap, textFarInset;
    if (isRight) {
      nearInset = rr.right - ir.right;      // image hugs the RIGHT row edge
      gap = ir.left - tr.right;             // clear space image<->text
      textFarInset = tr.left - rr.left;     // text hugs the LEFT row edge
    } else {
      nearInset = ir.left - rr.left;        // image hugs the LEFT row edge
      gap = tr.left - ir.right;
      textFarInset = rr.right - tr.right;   // text hugs the RIGHT row edge
    }
    measured.push({
      idx: i, side: isRight ? 'right' : 'left',
      imgWidth: round(ir.width), nearInset: round(nearInset),
      gap: round(gap), textFarInset: round(textFarInset),
      textTopGap: round(textTopGap), imgDeadFoot: round(imgDeadFoot),
      overlap: round(overlap), imgWidthFrac: round(imgWidthFrac),
      // document-space edges for annotation (viewport rect + scroll offset)
      geo: {
        rowL: rr.left + scrollX, rowR: rr.right + scrollX,
        imgL: ir.left + scrollX, imgR: ir.right + scrollX,
        txtL: tr.left + scrollX, txtR: tr.right + scrollX,
        top: rr.top + scrollY, bottom: rr.bottom + scrollY,
        imgTop: ir.top + scrollY, imgBottom: ir.bottom + scrollY,
        txtTop: tr.top + scrollY, txtBottom: tr.bottom + scrollY,
        hdrTop: hr.top + scrollY, imgElBottom: imr.bottom + scrollY,
      },
    });
  });

  // Per-metric median target + the worst per-row deviation; plus the image-left vs image-right
  // group-mean delta (the direct mirror test).
  const METRICS = ['imgWidth', 'nearInset', 'gap', 'textFarInset'];
  const median = (xs) => {
    if (!xs.length) return 0;
    const s = [...xs].sort((a, b) => a - b);
    const m = s.length >> 1;
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  };
  const mean = (xs) => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
  const lefts = measured.filter((r) => r.side === 'left');
  const rights = measured.filter((r) => r.side === 'right');
  const metrics = {};
  let worst = 0;
  for (const m of METRICS) {
    const all = measured.map((r) => r[m]);
    const med = median(all);
    let maxDev = 0, maxRow = -1;
    for (const r of measured) {
      const d = Math.abs(r[m] - med);
      if (d > maxDev) { maxDev = d; maxRow = r.idx; }
    }
    const mirror = Math.abs(mean(lefts.map((r) => r[m])) - mean(rights.map((r) => r[m])));
    metrics[m] = {
      median: round(med), maxDev: round(maxDev), maxRow,
      meanLeft: round(mean(lefts.map((r) => r[m]))),
      meanRight: round(mean(rights.map((r) => r[m]))),
      mirrorDelta: round(mirror),
    };
    worst = Math.max(worst, maxDev, mirror);
  }

  // Vertical alignment metrics: these have a FIXED target of 0 (not a median) -- the image must
  // sit flush with its heading top and carry no dead space under the picture, on EVERY row. The
  // worst absolute value across rows must stay within tol.
  const ALIGN = ['textTopGap', 'imgDeadFoot'];
  const align = {};
  let alignWorst = 0;
  for (const m of ALIGN) {
    let maxAbs = 0, maxRow = -1;
    for (const r of measured) {
      const a = Math.abs(r[m]);
      if (a > maxAbs) { maxAbs = a; maxRow = r.idx; }
    }
    align[m] = { target: 0, maxAbs: round(maxAbs), maxRow };
    alignWorst = Math.max(alignWorst, maxAbs);
  }
  worst = Math.max(worst, alignWorst);

  // MOBILE stacking metrics: a FIXED target of 0 overlap on EVERY row (the image must sit fully
  // above the text), and every row must have collapsed to one column (imgWidthFrac ~1). worst is
  // the largest positive overlap (0 when every row stacks clean).
  let maxOverlap = 0, overlapRow = -1, allStacked = true, minWidthFrac = 1;
  for (const r of measured) {
    if (r.overlap > maxOverlap) { maxOverlap = r.overlap; overlapRow = r.idx; }
    if (r.imgWidthFrac < minWidthFrac) minWidthFrac = r.imgWidthFrac;
    if (r.imgWidthFrac < 0.9) allStacked = false;
  }
  const mobile = { maxOverlap: round(maxOverlap), overlapRow, allStacked,
                   minWidthFrac: round(minWidthFrac) };

  const haveRows = measured.length > 0;
  let pass;
  if (mode === 'mobile') {
    worst = round(maxOverlap);
    pass = haveRows && maxOverlap <= tol && allStacked;
  } else {
    pass = worst <= tol && lefts.length > 0 && rights.length > 0;
  }

  return { mode, pass, worst: round(worst), tol, rows: measured, metrics, align, mobile,
           counts: { left: lefts.length, right: rights.length } };
}
"""


def _skip(msg: str) -> NoReturn:
    sys.stderr.write('website-image-text-row-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


def page_url(base: str, path: str) -> str:
    """Join the base origin and a page path, tolerating a path given without its
    leading slash (e.g. `--path wiki/About`): a bare `base + path` would yield
    `http://hostwiki/...`, which Playwright cannot load -- the page would be
    mis-reported rather than measured. Idempotent for an already-rooted path and
    the bare root `/` (the homepage, where the promo rows now live)."""
    return base.rstrip('/') + '/' + path.lstrip('/')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base', required=True,
                    help='served site origin, e.g. https://kicksecure-stage.github.io')
    ap.add_argument('--tol', type=float, default=SYM_MAX_PX,
                    help='offender budget in px (default %g)' % SYM_MAX_PX)
    # --path (repeatable) and --paths (a list) both feed the same page set; at
    # least one is required. A focused check wants explicit pages, not a full
    # tree sweep (the promo rows live on a handful of wiki pages).
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


# The two viewports every page is checked at: (mode, width, device_scale_factor).
# Both must stay clean -- a desktop fix must not regress mobile and vice versa, which
# is exactly what the operator asked this gate to guarantee.
_VIEWPORTS = (
    ('desktop', DESKTOP_WIDTH, 1.0),
    ('mobile', MOBILE_VIEWPORT, MOBILE_DSR),
)


def _describe(path: str, result: dict) -> str:
    """One-line offender reason for a failing page/mode (the numbers that broke it)."""
    if result['mode'] == 'mobile':
        mob = result['mobile']
        if not result['rows']:
            return 'mobile: no image-text rows found'
        return ('mobile: worst overlap %gpx on row %d (budget %g), allStacked=%s'
                % (mob['maxOverlap'], mob['overlapRow'], result['tol'], mob['allStacked']))
    if result['counts']['left'] == 0 or result['counts']['right'] == 0:
        return ('desktop: missing the image-left/right pair (left=%d right=%d)'
                % (result['counts']['left'], result['counts']['right']))
    return 'desktop: worst symmetry/alignment deviation %gpx (budget %g)' % (
        result['worst'], result['tol'])


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
                for mode, width, dsr in _VIEWPORTS:
                    page = browser.new_page(viewport={'width': width, 'height': 1000},
                                            device_scale_factor=dsr)
                    try:
                        resp = page.goto(url, timeout=NAV_TIMEOUT_MS)
                        if resp is not None and resp.status >= 400:
                            offenders += 1
                            sys.stderr.write('FAIL %s [%s]: served %d (not a real page)\n'
                                             % (path, mode, resp.status))
                            continue
                        page.wait_for_timeout(400)
                        checked += 1
                        result = page.evaluate(IMAGE_TEXT_ROW_JS,
                                               {'tol': args.tol, 'mode': mode})
                        if not result['pass']:
                            offenders += 1
                            sys.stderr.write('FAIL %s [%s]: %s\n'
                                             % (path, mode, _describe(path, result)))
                    finally:
                        page.close()
        finally:
            browser.close()

    if offenders:
        sys.stdout.write('website-image-text-row-tests: %d offending page/viewport(s) '
                         'across %d checks\n' % (offenders, checked))
        return 1
    sys.stdout.write('website-image-text-row-tests: %d checks clean -- every promo row '
                     'symmetric at %dpx and stacked clean at %dpx (budget %gpx)\n'
                     % (checked, DESKTOP_WIDTH, MOBILE_VIEWPORT, args.tol))
    return 0


if __name__ == '__main__':
    sys.exit(main())
