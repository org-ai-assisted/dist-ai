#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_tabthumb.py's probe + gate wiring -- the parts that do
NOT need a browser (Playwright is imported inside main()).

Canary cases:
 - the tab-thumb centering JS probe is present, non-empty, and keeps its measuring
   invariants (scopes the controller's direct .tcc-content > .tcc-section, measures
   the IMG not the .thumb wrapper, computes leftGap/rightGap/asym, isolate-activates
   one section, restores the original active state);
 - the offender threshold ASYM_MAX_PX is a sane positive px budget and is what
   main() actually compares against (a threshold defined but never evaluated gates
   nothing);
 - the phone width default is 390;
 - arg parsing: --base required, --width default, --path/--paths combine + dedup,
   page-path URL joining tolerates a missing leading slash, no paths errors.

Pure standard library, no network, no browser. Run directly: ./check_tabthumb_test.py
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
    from dist_ai.webcheck import tabthumb
    return tabthumb


def run():
    tt = _load()
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    # 1. The probe JS is present + non-empty (a defused JS string enforces nothing).
    check('TABTHUMB_JS present and non-empty',
          isinstance(tt.TABTHUMB_JS, str) and len(tt.TABTHUMB_JS.strip()) > 0)
    # Measuring invariants: scope the controller's OWN direct content sections,
    # isolate-activate one, measure the IMG vs the .tcc-content content box.
    check('probe scopes controller direct tcc-content sections',
          ".tab-content-controller" in tt.TABTHUMB_JS
          and ":scope > .tcc-content > .tcc-section" in tt.TABTHUMB_JS)
    check('probe measures the IMG, not the .thumb wrapper',
          "thumb.querySelector('img')" in tt.TABTHUMB_JS
          and 'img.getBoundingClientRect()' in tt.TABTHUMB_JS)
    check('probe computes leftGap/rightGap/asym',
          'leftGap' in tt.TABTHUMB_JS and 'rightGap' in tt.TABTHUMB_JS
          and 'asym' in tt.TABTHUMB_JS and 'Math.abs(leftGap - rightGap)' in tt.TABTHUMB_JS)
    check('probe subtracts the pane padding + client border',
          'pane.clientLeft' in tt.TABTHUMB_JS and 'paddingLeft' in tt.TABTHUMB_JS
          and 'paddingRight' in tt.TABTHUMB_JS)
    check('probe isolate-activates one section',
          "classList.remove('active')" in tt.TABTHUMB_JS
          and "classList.add('active')" in tt.TABTHUMB_JS)
    check('probe restores the original active state',
          'origActive' in tt.TABTHUMB_JS and 'classList.toggle' in tt.TABTHUMB_JS)

    # 2. Threshold + width constants sane.
    check('ASYM_MAX_PX is a sane positive px budget',
          isinstance(tt.ASYM_MAX_PX, int) and 1 <= tt.ASYM_MAX_PX <= 60,
          repr(tt.ASYM_MAX_PX))
    check('VIEWPORT default is 390', tt.VIEWPORT == 390, repr(tt.VIEWPORT))

    # 3. The threshold must be WIRED into main() (defined-but-unused gates nothing),
    #    and compared as an OFFENDER cutoff on asym.
    main_body = inspect.getsource(tt.main)
    check('probe JS evaluated in main', 'TABTHUMB_JS' in main_body
          and 'page.evaluate' in main_body)
    check('threshold compared in main', 'ASYM_MAX_PX' in main_body
          and "t['asym'] > ASYM_MAX_PX" in main_body)
    # Browser-unavailable is a clean SKIP (77), not a hard failure or a false green.
    check('browser-unavailable is a SKIP (77)',
          '_skip(' in main_body and 'SystemExit(77)' in inspect.getsource(tt._skip))
    check('clean run returns 0, offenders return 1',
          'return 1' in main_body and 'return 0' in main_body)

    # 4. Arg parsing (browser-free): --base required, --width default, --path/--paths
    #    combine + dedup, and no paths is an error.
    ap = tt.build_parser()
    parsed = ap.parse_args(['--base', 'http://x', '--path', '/wiki/VirtualBox'])
    check('--base + --path parses', parsed.base == 'http://x'
          and parsed.path == ['/wiki/VirtualBox'])
    check('--width defaults to VIEWPORT', parsed.width == tt.VIEWPORT, repr(parsed.width))
    parsed = ap.parse_args(['--base', 'http://x', '--path', '/a', '--path', '/a',
                            '--paths', '/b', '/a'])
    check('--path + --paths combine and dedup, order kept',
          tt._paths_from(parsed) == ['/a', '/b'], repr(tt._paths_from(parsed)))
    # --base is required: parsing without it must error (SystemExit from argparse).
    try:
        tt.build_parser().parse_args(['--path', '/x'])
        check('--base is required', False)
    except SystemExit:
        check('--base is required', True)
    # no paths given -> _paths_from yields nothing (main() errors on that).
    parsed = ap.parse_args(['--base', 'http://x'])
    check('no paths -> empty page list', tt._paths_from(parsed) == [],
          repr(tt._paths_from(parsed)))

    # page_url: a path missing its leading slash must still produce a loadable URL
    # (else base+path -> http://hostwiki/... which Playwright cannot load).
    check('page_url rooted path', tt.page_url('http://x', '/wiki/VirtualBox')
          == 'http://x/wiki/VirtualBox')
    check('page_url missing-slash normalized', tt.page_url('http://x/', 'wiki/VirtualBox')
          == 'http://x/wiki/VirtualBox')
    check('page_url root', tt.page_url('http://x', '/') == 'http://x/')

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        line = 'check_tabthumb_test: %s %s' % ('pass' if ok else 'FAIL', name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_tabthumb_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
