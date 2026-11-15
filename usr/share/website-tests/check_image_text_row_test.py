#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_image_text_row.py's probe + gate wiring -- the parts
that do NOT need a browser (Playwright is imported inside main()).

Canary cases:
 - the promo-row measurement JS probe is present, non-empty, and keeps its
   measuring invariants (selects .left-right-image-text, scopes each row's direct
   .image / .text, measures the mirror metrics, the fixed-target-0 alignment
   metrics textTopGap / imgDeadFoot, and the mobile stacking overlap /
   imgWidthFrac, and returns a per-mode pass);
 - the offender budget SYM_MAX_PX is a sane positive px budget and is what main()
   actually gates against (a threshold defined but never evaluated gates nothing);
 - the two validated viewports are desktop 1350 (DPR 1) and mobile 412 (DPR 1.75),
   and main() checks BOTH per page;
 - browser-unavailable is a clean SKIP (77);
 - arg parsing: --base required, --tol default, --path/--paths combine + dedup,
   page-path URL joining tolerates a missing leading slash (incl. the bare root /).

Pure standard library, no network, no browser. Run directly: ./check_image_text_row_test.py
"""

import inspect
import os
import sys


def _load():
    # The browser lane lives in the importable core; import it (its real home).
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    # (safe: the playwright import is inside the core module's main(), not at import)
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import image_text_row
    return image_text_row


def run():
    it = _load()
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    js = it.IMAGE_TEXT_ROW_JS
    # 1. The probe JS is present + non-empty (a defused JS string enforces nothing).
    check('IMAGE_TEXT_ROW_JS present and non-empty',
          isinstance(js, str) and len(js.strip()) > 0)
    # Measuring invariants: select the promo rows, scope each row's direct image / text.
    check('probe selects the promo rows',
          ".left-right-image-text" in js)
    check('probe scopes each row direct image/text',
          ":scope > .image" in js and ":scope > .text" in js)
    # Desktop mirror metrics + the group-mean mirror delta.
    check('probe computes the mirror metrics',
          "imgWidth" in js and "nearInset" in js and "gap" in js
          and "textFarInset" in js and "mirrorDelta" in js)
    # Fixed-target-0 vertical alignment metrics (the desktop float-above-heading bug).
    check('probe computes textTopGap / imgDeadFoot alignment',
          "textTopGap" in js and "imgDeadFoot" in js
          and "firstElementChild" in js)
    # Mobile stacking: deepest image foot vs text top, and the one-column confirmation.
    check('probe computes mobile overlap + imgWidthFrac',
          "overlap" in js and "deepImgFoot" in js and "imgWidthFrac" in js
          and "allStacked" in js)
    # Per-mode pass: mobile gates overlap+stacked, desktop gates worst + the L/R pair.
    check('probe returns a per-mode pass',
          "mode === 'mobile'" in js and "lefts.length > 0 && rights.length > 0" in js
          and "maxOverlap <= tol && allStacked" in js)

    # 2. Budget + viewport constants sane.
    check('SYM_MAX_PX is a sane positive px budget',
          isinstance(it.SYM_MAX_PX, (int, float)) and 0 < it.SYM_MAX_PX <= 60,
          repr(it.SYM_MAX_PX))
    check('DESKTOP_WIDTH is 1350', it.DESKTOP_WIDTH == 1350, repr(it.DESKTOP_WIDTH))
    check('MOBILE_VIEWPORT is 412', it.MOBILE_VIEWPORT == 412, repr(it.MOBILE_VIEWPORT))
    check('MOBILE_DSR is 1.75', it.MOBILE_DSR == 1.75, repr(it.MOBILE_DSR))
    # The two viewports main() actually checks must be exactly those two.
    check('both viewports wired',
          it._VIEWPORTS == (('desktop', 1350, 1.0), ('mobile', 412, 1.75)),
          repr(it._VIEWPORTS))

    # 3. The probe + budget must be WIRED into main() (defined-but-unused gates nothing).
    main_body = inspect.getsource(it.main)
    check('probe JS evaluated in main', 'IMAGE_TEXT_ROW_JS' in main_body
          and 'page.evaluate' in main_body)
    check('budget gated in main', "not result['pass']" in main_body
          and 'args.tol' in main_body)
    check('main checks both viewports per page', '_VIEWPORTS' in main_body)
    # Browser-unavailable is a clean SKIP (77), not a hard failure or a false green.
    check('browser-unavailable is a SKIP (77)',
          '_skip(' in main_body and 'SystemExit(77)' in inspect.getsource(it._skip))
    check('clean run returns 0, offenders return 1',
          'return 1' in main_body and 'return 0' in main_body)

    # 4. Arg parsing (browser-free): --base required, --tol default, --path/--paths
    #    combine + dedup, and no paths is an error.
    ap = it.build_parser()
    parsed = ap.parse_args(['--base', 'http://x', '--path', '/'])
    check('--base + --path parses', parsed.base == 'http://x'
          and parsed.path == ['/'])
    check('--tol defaults to SYM_MAX_PX', parsed.tol == it.SYM_MAX_PX, repr(parsed.tol))
    parsed = ap.parse_args(['--base', 'http://x', '--path', '/a', '--path', '/a',
                            '--paths', '/b', '/a'])
    check('--path + --paths combine and dedup, order kept',
          it._paths_from(parsed) == ['/a', '/b'], repr(it._paths_from(parsed)))
    # --base is required: parsing without it must error (SystemExit from argparse).
    try:
        it.build_parser().parse_args(['--path', '/x'])
        check('--base is required', False)
    except SystemExit:
        check('--base is required', True)
    # no paths given -> _paths_from yields nothing (main() errors on that).
    parsed = ap.parse_args(['--base', 'http://x'])
    check('no paths -> empty page list', it._paths_from(parsed) == [],
          repr(it._paths_from(parsed)))

    # page_url: a path missing its leading slash must still produce a loadable URL
    # (else base+path -> http://hostwiki/... which Playwright cannot load); the bare
    # root / (the homepage carrier) stays loadable.
    check('page_url rooted path', it.page_url('http://x', '/wiki/About')
          == 'http://x/wiki/About')
    check('page_url missing-slash normalized', it.page_url('http://x/', 'wiki/About')
          == 'http://x/wiki/About')
    check('page_url root', it.page_url('http://x', '/') == 'http://x/')

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        line = 'check_image_text_row_test: %s %s' % ('pass' if ok else 'FAIL', name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_image_text_row_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
