#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_footer.py (the footer row-alignment guard) -- the
parts that do NOT need a browser (Playwright is imported inside main()).

Canary cases for the misalignment predicate (it must flag the real bug AND leave
aligned footers alone -- a predicate that flags nothing, or everything, enforces
nothing):
 - four rows sharing one gutter -> nothing flagged;
 - one row (the .ffree shape) offset ~20px left -> that row flagged, on the left axis;
 - a row offset only on the RIGHT -> flagged, on the right axis;
 - a deviation just within TOL -> not flagged; just over TOL -> flagged;
 - fewer than two rows -> nothing to compare -> not flagged.
Also: constants sane, the measurement reads the content box (padding removed),
and the predicate is actually WIRED into main().

Pure standard library, no network, no browser. Run directly: ./check_footer_test.py
"""

import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        'check_footer', os.path.join(_HERE, 'check_footer.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)          # safe: playwright import is inside main()
    return module


def _row(name, left, right):
    return {'name': name, 'left': left, 'right': right}


def _aligned():
    # ftop / fshare / ffree / fbot all inset the same 20px gutter inside a
    # centered 1080px container at a 1440px viewport.
    return [_row('.ftop', 200, 1240), _row('.fshare', 200, 1240),
            _row('.ffree', 200, 1240), _row('.fbot', 200, 1240)]


def run():
    cf = _load()
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    # 1. aligned footer: nothing flagged.
    check('aligned rows not flagged', not cf.misaligned_rows(_aligned()))

    # 2. the real bug: .ffree zeroes its gutter -> its content box sits 20px left
    #    and 20px further right; must be flagged (and only it).
    rows = _aligned()
    rows[2] = _row('.ffree', 180, 1260)
    offs = cf.misaligned_rows(rows)
    check('offset row flagged', len(offs) == 1 and offs[0]['name'] == '.ffree', repr(offs))
    check('offset reported on left axis',
          bool(offs) and offs[0]['axis'] == 'left', repr(offs))

    # 3. a row offset only on the RIGHT (padding-right dropped) is caught too.
    rows = _aligned()
    rows[1] = _row('.fshare', 200, 1260)
    offs = cf.misaligned_rows(rows)
    check('right-only offset flagged',
          len(offs) == 1 and offs[0]['name'] == '.fshare' and offs[0]['axis'] == 'right',
          repr(offs))

    # 4. tolerance boundary: within TOL passes, just over TOL fails.
    rows = _aligned()
    rows[0] = _row('.ftop', 200 + cf.TOL, 1240)
    check('deviation at TOL not flagged', not cf.misaligned_rows(rows), repr(rows[0]))
    rows[0] = _row('.ftop', 200 + cf.TOL + 1, 1240)
    check('deviation over TOL flagged', bool(cf.misaligned_rows(rows)))

    # 5. fewer than two rows -> nothing to compare.
    check('single row not flagged', not cf.misaligned_rows([_row('.ffree', 180, 1260)]))
    check('empty not flagged', not cf.misaligned_rows([]))

    # 6. constants sane.
    check('TOL is a small positive px', 0 < cf.TOL <= 5, repr(cf.TOL))
    check('measures a desktop and a phone width',
          any(w >= 1200 for w in cf.FOOTER_WIDTHS)
          and any(w <= 480 for w in cf.FOOTER_WIDTHS), repr(cf.FOOTER_WIDTHS))

    # 7. the measurement must read the CONTENT box (padding removed), else a row
    #    that keeps its width but zeroes its gutter would not be seen.
    check('measurement removes padding',
          'paddingLeft' in cf._MEASURE_JS and 'paddingRight' in cf._MEASURE_JS)
    check('measurement iterates footer children',
          'footer.children' in cf._MEASURE_JS)
    check('measurement skips script rows', "'SCRIPT'" in cf._MEASURE_JS)

    # 8. the predicate must be WIRED into main() (defined-but-unused enforces nothing).
    with open(os.path.join(_HERE, 'check_footer.py'), encoding='utf-8') as handle:
        body = handle.read()
    main_body = body[body.index('def main('):]
    check('predicate wired into main', 'misaligned_rows(' in main_body)
    check('measurement evaluated in main', '_MEASURE_JS' in main_body)

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        line = 'check_footer_test: %s %s' % ('pass' if ok else 'FAIL', name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_footer_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
