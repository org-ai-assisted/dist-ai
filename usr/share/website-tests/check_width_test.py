#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_width.py (the desktop width-utilization "virtual
ruler") -- the parts that do NOT need a browser (Playwright is imported inside
main()).

Canary cases for the offender predicate (a stubbed narrow section MUST flag, and
each exemption MUST let a section through -- a predicate that flags nothing, or
everything, enforces nothing):
 - a tall, text-heavy, narrow single-column section with no wide element -> OFFENDER;
 - a section whose content fills the width (a grid, extUtil ~1.0) -> not flagged;
 - a short section (below the height floor) -> not flagged even if narrow;
 - a section holding a wide table/figure (wideUtil high) -> not flagged;
 - a light section (few chars) -> not flagged.
Also: constants sane, the extent metric counts form controls/media (the
false-positive that a full-width <textarea> is wasted space), and the predicate
is actually WIRED into main().

Pure standard library, no network, no browser. Run directly: ./check_width_test.py
"""

import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        'check_width', os.path.join(_HERE, 'check_width.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)          # safe: playwright import is inside main()
    return module


def _sec(extUtil=0.63, wideUtil=0.0, secH=600, nchars=800):
    return {'id': 's', 'cls': 'cat', 'avail': 1000,
            'extUtil': extUtil, 'wideUtil': wideUtil, 'secH': secH,
            'nchars': nchars, 'sample': 'x'}


def run():
    cw = _load()
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    # 1. offender predicate: the base narrow-tall-heavy-noWide case flags ...
    check('narrow tall text section is an offender', cw.is_offender(_sec()))
    # ... and every exemption lets a section through (canary the gut, not just the pass)
    check('full-width section not flagged',
          not cw.is_offender(_sec(extUtil=0.98)))
    check('just-at-threshold section not flagged',
          not cw.is_offender(_sec(extUtil=cw.MIN_UTIL)))
    check('short section not flagged',
          not cw.is_offender(_sec(secH=cw.MIN_SECTION_PX - 1)))
    check('wide-element section not flagged',
          not cw.is_offender(_sec(wideUtil=0.95)))
    check('light section not flagged',
          not cw.is_offender(_sec(nchars=cw.MIN_CHARS - 1)))

    # 2. constants sane
    check('MIN_UTIL is a sensible fraction', 0.5 < cw.MIN_UTIL < 0.95, repr(cw.MIN_UTIL))
    check('desktop width is a desktop', cw.DESKTOP_WIDTH >= 1200, repr(cw.DESKTOP_WIDTH))
    check('wide-exempt above min-util', cw.WIDE_EXEMPT >= cw.MIN_UTIL, repr(cw.WIDE_EXEMPT))

    # 3. the extent metric must count form controls / media, else a full-width
    #    <textarea> or image reads as an empty section (a real false positive fixed).
    check('extent counts form controls + media',
          'FILL_TAGS' in cw._MEASURE_JS and 'TEXTAREA' in cw._MEASURE_JS)
    check('extent unions text blocks',
          'extMinL' in cw._MEASURE_JS and 'extentW' in cw._MEASURE_JS)

    # 4. the predicate must be WIRED into main() (defined-but-unused enforces nothing).
    with open(os.path.join(_HERE, 'check_width.py'), encoding='utf-8') as handle:
        body = handle.read()
    main_body = body[body.index('def main('):]
    check('offender predicate wired into main', 'is_offender(' in main_body)
    check('measurement evaluated in main', '_MEASURE_JS' in main_body)

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        line = 'check_width_test: %s %s' % ('pass' if ok else 'FAIL', name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_width_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
