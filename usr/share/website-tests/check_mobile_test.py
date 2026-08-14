#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_mobile.py's page discovery and gate wiring -- the
parts that do NOT need a browser (Playwright is imported inside main()).

Canary cases:
 - an image-render template (.html with a same-basename image sibling) is NOT
   treated as a page, for a .webp sibling as well as .png (the bug: logo-wide.html
   with a .webp sibling was page-checked and falsely reported horizontal overflow);
 - a real .html with no image sibling IS a page;
 - index.html collapses to its directory URL;
 - the rendered-layout gates (header budget, overflow, contrast walk) are wired
   into main() -- a check defined but never evaluated enforces nothing.

Pure standard library, no network, no browser. Run directly: ./check_mobile_test.py
"""

import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        'check_mobile', os.path.join(_HERE, 'check_mobile.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)          # safe: playwright import is inside main()
    return module


def _write(root, rel, data='x'):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)


def run():
    cm = _load()
    results = []

    def check(name, cond, detail=''):
        results.append((name, bool(cond), detail))

    # 1. image-render templates skipped for BOTH .png and .webp siblings; a real
    #    page is kept. logo-wide.html + logo-wide.webp must NOT appear.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html')
        _write(root, 'og.html'); _write(root, 'og.png')                 # png template
        _write(root, 'logo-wide.html'); _write(root, 'logo-wide.webp')  # webp template
        _write(root, 'paste/index.html')                                # real page
        urls = cm._page_urls(root)
        check('png render template skipped', '/og.html' not in urls, repr(urls))
        check('webp render template skipped', '/logo-wide.html' not in urls, repr(urls))
        check('real subpage kept', '/paste/' in urls, repr(urls))
        check('index collapses to dir', '/' in urls, repr(urls))

    # 2. Constants sane: the phone width is in the overflow set; header budget is
    #    a compact bar; the contrast + header JS are non-empty and self-consistent.
    check('VIEWPORT in OVERFLOW_WIDTHS', cm.VIEWPORT in cm.OVERFLOW_WIDTHS,
          repr(cm.OVERFLOW_WIDTHS))
    check('header budget is a compact bar', 40 <= cm.HEADER_MAX_PX <= 140,
          repr(cm.HEADER_MAX_PX))
    check('contrast JS exempts code mockups',
          "closest('pre, .term, .copybox')" in cm._CONTRAST_JS)
    check('contrast JS uses WCAG thresholds',
          '4.5' in cm._CONTRAST_JS and '3.0' in cm._CONTRAST_JS)

    # 3. The rendered-layout gates must be WIRED into main() (defined-but-unused
    #    silently enforces nothing).
    with open(os.path.join(_HERE, 'check_mobile.py'), encoding='utf-8') as handle:
        main_body = handle.read()
    main_body = main_body[main_body.index('def main('):]
    check('overflow widths iterated in main', 'for width in OVERFLOW_WIDTHS' in main_body)
    check('header gate wired', '_HEADER_JS' in main_body and 'HEADER_MAX_PX' in main_body)
    check('contrast gate wired', '_CONTRAST_JS' in main_body)
    check('header-overlap sweep wired',
          'for width in HEADER_SWEEP_WIDTHS' in main_body
          and '_HEADER_OVERLAP_JS' in main_body)

    # 4. Header-overlap detection is configured: a range of sweep widths (not a
    #    single one) and the icon<->label logic present in the JS.
    check('header sweep covers >=4 widths', len(cm.HEADER_SWEEP_WIDTHS) >= 4,
          repr(cm.HEADER_SWEEP_WIDTHS))
    check('overlap JS checks icon<->label gap',
          'overlaps its icon' in cm._HEADER_OVERLAP_JS
          and 'header items overlap' in cm._HEADER_OVERLAP_JS)

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        line = 'check_mobile_test: %s %s' % ('pass' if ok else 'FAIL', name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_mobile_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
