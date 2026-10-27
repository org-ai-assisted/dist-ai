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

import inspect
import os
import sys
import tempfile


def _load():
    # the browser lane lives in the importable core; import it (its real home).
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    # (safe: the playwright import is inside the core module's main(), not at import)
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import mobile
    return mobile


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
    # New-audit JS content sanity (a defused JS string enforces nothing).
    # Element-overflow (ported, validated): must keep the FP-avoidance invariants
    # -- only overflow-x:visible spills, by-design scroll surfaces are exempt, and
    # an out-of-flow descendant does not count.
    check('element-overflow JS flags only overflow-x:visible',
          "cs.overflowX !== 'visible'" in cm._ELEMENT_OVERFLOW_JS)
    check('element-overflow JS exempts by-design scroll surfaces',
          'EXEMPT_ANCESTOR' in cm._ELEMENT_OVERFLOW_JS
          and 'pre' in cm._ELEMENT_OVERFLOW_EXEMPT and 'table' in cm._ELEMENT_OVERFLOW_EXEMPT)
    # Widened (0-FP preserving): flag an in-flow descendant past the edge OR a
    # text-only overflow with no descendant past; skip ONLY out-of-flow-only.
    check('element-overflow JS skips out-of-flow-only, catches text-only',
          "ccs.position !== 'absolute'" in cm._ELEMENT_OVERFLOW_JS
          and 'inFlowPast' in cm._ELEMENT_OVERFLOW_JS
          and 'anyDescendantPast' in cm._ELEMENT_OVERFLOW_JS
          and '!inFlowPast && anyDescendantPast' in cm._ELEMENT_OVERFLOW_JS)
    # Canonical shared shape: STRUCTURED objects (the mw-static tool imports these
    # and formats its own line); string formatting lives in the consumer's reporter.
    check('element-overflow JS returns structured {sel,over,sw,cw,text}',
          'sel:' in cm._ELEMENT_OVERFLOW_JS and 'sw:' in cm._ELEMENT_OVERFLOW_JS
          and 'cw:' in cm._ELEMENT_OVERFLOW_JS and 'text:' in cm._ELEMENT_OVERFLOW_JS)
    check('element-overflow scope targets family content boxes',
          '.issue' in cm._ELEMENT_OVERFLOW_SCOPE)
    check('broken-image JS uses complete && naturalWidth===0',
          'img.complete' in cm._BROKEN_IMG_JS and 'naturalWidth === 0' in cm._BROKEN_IMG_JS)
    check('broken-image JS returns structured {src,alt}',
          'src:' in cm._BROKEN_IMG_JS and 'alt:' in cm._BROKEN_IMG_JS)
    # The lazy-position skip was a false-pass (complete is already false for an
    # unloaded lazy image; the skip only hid broken lazy images past ~1.5vh). It
    # must NOT come back -- these sites' galleries are lazy. (dev1238 / 61d6c25)
    check('broken-image JS has no lazy-position false-pass skip',
          "loading === 'lazy'" not in cm._BROKEN_IMG_JS
          and 'innerHeight * 2' not in cm._BROKEN_IMG_JS)
    # The high-FP generic body-overlap heuristic must NOT come back (inline wrap FP).
    check('no generic body-overlap heuristic', not hasattr(cm, '_OVERLAP_JS'))
    # The mount server must swallow a client-aborted connection (a no-JS page that
    # stops at domcontentloaded aborts in-flight image loads -> BrokenPipeError),
    # so a harmless disconnect never dumps a traceback that reads as a failure.
    srv = object.__new__(cm._MountingTCPServer)
    try:
        raise BrokenPipeError('client went away')
    except BrokenPipeError:
        _raised = False
        try:
            cm._MountingTCPServer.handle_error(srv, None, ('127.0.0.1', 0))
        except Exception:                      # noqa: BLE001 -- must NOT re-raise
            _raised = True
        check('mount server swallows a client-aborted connection', not _raised)
    # broken-image must EXEMPT svg (naturalWidth===0 is unreliable for a
    # dimensionless SVG on Gecko/WebKit -> cross-engine false positive).
    check('broken-image JS exempts svg', '.svg' in cm._BROKEN_IMG_JS)
    # contrast fallback canvas is scheme-aware (white in light, dark in dark) --
    # assuming white under color-scheme:dark mis-scored transparent-bg text.
    check('contrast JS takes a scheme default canvas', '(dflt)' in cm._CONTRAST_JS
          and 'return dflt' in cm._CONTRAST_JS)
    check('dark canvas default is dark', cm._CANVAS_DARK['r'] < 64
          and cm._CANVAS_LIGHT['r'] == 255, repr(cm._CANVAS_DARK))
    check('both color schemes named', set(cm.COLOR_SCHEMES) == {'light', 'dark'},
          repr(cm.COLOR_SCHEMES))

    # 3. The rendered-layout gates must be WIRED into main() (defined-but-unused
    #    silently enforces nothing).
    main_body = inspect.getsource(cm.main)
    check('overflow widths iterated in main', 'for width in OVERFLOW_WIDTHS' in main_body)
    check('header gate wired', '_HEADER_JS' in main_body and 'HEADER_MAX_PX' in main_body)
    check('contrast gate wired', '_CONTRAST_JS' in main_body)
    check('header-overlap sweep wired',
          'for width in HEADER_SWEEP_WIDTHS' in main_body
          and '_HEADER_OVERLAP_JS' in main_body)
    # Added audits must be wired too.
    check('element-overflow gate wired', '_ELEMENT_OVERFLOW_JS' in main_body)
    check('broken-image gate wired', '_BROKEN_IMG_JS' in main_body)
    check('dark-scheme contrast wired',
          "color_scheme='dark'" in main_body and '(dark)' in main_body
          and '_CANVAS_DARK' in main_body)
    check('no-JS lane wired',
          'java_script_enabled=False' in main_body and '_NOJS_JS' in main_body)
    check('anchor-occlusion gate wired', '_ANCHOR_OCCLUSION_JS' in main_body)
    # Empirical, not a static CSS model: navigate the fragment, then measure where
    # the target lands vs the header bottom (the browser handles scroll-padding/
    # margin/clamping). Must skip invisible sticky/fixed elements as the header.
    check('anchor-occlusion JS measures real fragment navigation',
          'location.hash' in cm._ANCHOR_OCCLUSION_JS
          and 'getBoundingClientRect' in cm._ANCHOR_OCCLUSION_JS
          and "'sticky'" in cm._ANCHOR_OCCLUSION_JS and "'fixed'" in cm._ANCHOR_OCCLUSION_JS
          and 'visibility' in cm._ANCHOR_OCCLUSION_JS)
    check('no-JS probes content + layout (ancestor-visibility aware)',
          'h1' in cm._NOJS_JS and 'textlen' in cm._NOJS_JS
          and 'overflow' in cm._NOJS_JS and 'checkVisibility' in cm._NOJS_JS)
    # The fragile nav assertion was dropped (navless standalone views + links in a
    # sibling list outside header/nav both false-fail); it must not come back.
    check('no-JS has no fragile nav assertion',
          'navlinks' not in cm._NOJS_JS and 'hasnav' not in cm._NOJS_JS)
    check('no-JS min-text threshold is a sane positive', cm._NOJS_MIN_TEXT >= 50,
          repr(cm._NOJS_MIN_TEXT))
    # no-JS goto waits domcontentloaded, not load -- an image-heavy gallery exceeds
    # the load timeout with JS off.
    check('no-JS goto waits domcontentloaded',
          "wait_until='domcontentloaded'" in main_body)
    # Flake fix: domcontentloaded fires before external CSS applies, so a fixed sleep
    # raced CSS application under host load and false-flagged "no-JS overflow" on random
    # pages (an unstyled layout is wider). The no-JS lane must poll link.sheet until the
    # stylesheet APPLIES before measuring overflow. Canary: fails on the pre-fix code,
    # which had only a fixed wait_for_timeout here.
    check('no-JS lane waits for stylesheets to apply before measuring overflow',
          '_STYLESHEETS_READY_JS' in main_body and 'CSS_APPLY_POLLS' in main_body)
    check('stylesheets-ready probe keys on link.sheet (the CSS-applied signal)',
          'l.sheet' in getattr(cm, '_STYLESHEETS_READY_JS', '')
          and 'stylesheet' in getattr(cm, '_STYLESHEETS_READY_JS', ''))
    # Silent-skip regression (0 pages + a launch failure): the failure return must
    # come BEFORE the checked==0 _skip, so a recorded failure surfaces as exit 1.
    check('failure return precedes the no-pages skip',
          main_body.index('if failures:') < main_body.index("_skip('no pages served"))
    check('multi-engine loop wired',
          '_browsers_from_env' in main_body and 'for engine_name, browser in engines' in main_body)
    # Silent-skip regression: `primary` must be the first LAUNCHED engine, not
    # browsers[0]. If chromium (browsers[0]) fails to launch but another engine
    # runs, keying `primary`/`checked` off browsers[0] leaves checked==0 -> _skip(77),
    # swallowing the launch failure as a SKIP. Must derive primary from `engines`.
    check('primary is the first LAUNCHED engine (not browsers[0])',
          'primary = engines[0][0]' in main_body and 'primary = browsers[0]' not in main_body)

    # 3b. Engine selection: default is chromium (primary), env overrides, dedup,
    #     and a launch-failure classification exists (loud when another engine ran).
    _save = os.environ.pop('WEBCHECK_BROWSERS', None)
    try:
        check('default engine is chromium-only', cm._browsers_from_env() == ['chromium'])
        os.environ['WEBCHECK_BROWSERS'] = 'chromium, chromium, firefox'
        check('engine list dedups preserving order',
              cm._browsers_from_env() == ['chromium', 'firefox'],
              repr(cm._browsers_from_env()))
    finally:
        if _save is None:
            os.environ.pop('WEBCHECK_BROWSERS', None)
        else:
            os.environ['WEBCHECK_BROWSERS'] = _save
    check('primary engine drives color audits only',
          'is_primary' in main_body
          and main_body.index("color_scheme='dark'") > main_body.index('is_primary'))
    check('requested-but-missing engine is a loud failure (not silent skip)',
          "unavailable" in main_body and 'failures += 1' in main_body
          and 'name == browsers[-1]' in main_body)

    # 4. Header-overlap detection is configured: a range of sweep widths (not a
    #    single one) and the icon<->label logic present in the JS.
    check('header sweep covers >=4 widths', len(cm.HEADER_SWEEP_WIDTHS) >= 4,
          repr(cm.HEADER_SWEEP_WIDTHS))
    check('overlap JS checks icon<->label gap',
          'overlaps its icon' in cm._HEADER_OVERLAP_JS
          and 'header items overlap' in cm._HEADER_OVERLAP_JS)

    # _MountHandler containment: an in-tree symlink whose target escapes the served root must be
    # REFUSED (not served to the network-capable browser) -- a real exfil surface (ai-review grok).
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        _write(root, 'ok.html')
        secret = os.path.join(outside, 'secret.txt')
        with open(secret, 'w', encoding='utf-8') as fh:
            fh.write('TOP SECRET')
        os.symlink(secret, os.path.join(root, 'leak.txt'))

        class _Srv:
            mounts: dict = {}
        handler = object.__new__(cm._MountHandler)   # bypass __init__ (needs a live socket)
        handler.directory = root
        handler.server = _Srv()
        ok_path = handler.translate_path('/ok.html')
        leaked = handler.translate_path('/leak.txt')
        check('_MountHandler serves a normal in-root file',
              os.path.realpath(ok_path) == os.path.realpath(os.path.join(root, 'ok.html')),
              repr(ok_path))
        check('_MountHandler REFUSES an out-of-root symlink (no exfil to the browser)',
              '__forbidden__' in leaked and 'secret' not in os.path.basename(leaked), repr(leaked))

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
