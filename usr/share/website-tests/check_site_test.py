#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_site.py's image checks: the orphaned-image guard
(check_assets), the content-image format gate (check_image_format), and the
render-source recognition (html_files) they lean on.

Fails on the pre-guard check_site.py: check_assets does not exist there, so the
import below raises AttributeError -- the guard cannot silently regress away.

Canary cases (would pass a naive HTML-only implementation only by accident):
 - a logo referenced ONLY from README.md must NOT be flagged (the real
   false-positive found in output-lies.github.io);
 - a background referenced ONLY from a CSS url() must NOT be flagged;
 - an image named by nothing MUST be flagged;
 - a logo.png masked by a substring of osi-logo.png MUST still be flagged
   (whole-token match, not raw substring);
 - a content .png reference MUST be flagged, the same as .webp must NOT.

Pure standard library, no network. Run directly: ./check_site_test.py
"""

import importlib.util
import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_check_site():
    spec = importlib.util.spec_from_file_location(
        'check_site', os.path.join(_HERE, 'check_site.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)


def _png(root, rel):
    # A minimal real PNG (1x1) so the file is a genuine image, not a text stub.
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00'
            b'\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc'
            b'\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82')


def _assets_failures(check_site, root):
    failures = []
    check_site.check_assets(root, failures)
    return failures


def run():
    check_site = _load_check_site()
    results = []   # (name, ok, detail)

    def check(name, condition, detail=''):
        results.append((name, bool(condition), detail))

    # 1. An image named by an HTML page is clean; an image named by nothing is flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<img src="shots/used.png">')
        _png(root, 'shots/used.png')
        _png(root, 'shots/dead.png')
        fails = _assets_failures(check_site, root)
        flagged = ' '.join(fails)
        check('orphan flagged', 'shots/dead.png' in flagged, flagged)
        check('referenced not flagged', 'shots/used.png' not in flagged, flagged)
        check('exactly one failure', len(fails) == 1, repr(fails))

    # 2. Canary: a logo referenced ONLY from README.md must NOT be flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<p>no image here</p>')
        _write(root, 'README.md', '`logo.png` is the organization logo.\n')
        _png(root, 'logo.png')
        fails = _assets_failures(check_site, root)
        check('README-only logo cleared', fails == [], repr(fails))

    # 3. Canary: a background referenced ONLY from a CSS url() must NOT be flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<link rel="stylesheet" href="style.css">')
        _write(root, 'style.css', 'body{background:url(bg.png)}')
        _png(root, 'bg.png')
        fails = _assets_failures(check_site, root)
        check('CSS-url background cleared', fails == [], repr(fails))

    # 4. Canary: an icon named only in a web manifest must NOT be flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<link rel="manifest" href="site.webmanifest">')
        _write(root, 'site.webmanifest', '{"icons":[{"src":"icon-192.png"}]}')
        _png(root, 'icon-192.png')
        fails = _assets_failures(check_site, root)
        check('manifest icon cleared', fails == [], repr(fails))

    # 5. Canary: a logo referenced only from .github/README.md must NOT be flagged.
    # A '/.git' substring skip drops '.github' too, so the reference goes unread
    # and the logo is falsely orphaned; only exact-name pruning reads it.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<p>no image here</p>')
        _write(root, '.github/README.md', '`org-logo.png` is the org logo.\n')
        _png(root, 'org-logo.png')
        fails = _assets_failures(check_site, root)
        check('.github reference cleared', fails == [], repr(fails))

    # 6. The git metadata dir must NOT be scanned for images (would add noise and
    # be catastrophic on a real .git). An image path under .git is ignored.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<p>no image here</p>')
        _png(root, '.git/objects/stray.png')
        fails = _assets_failures(check_site, root)
        check('.git contents ignored', fails == [], repr(fails))

    # 7. check_assets matches basenames as WHOLE tokens, not raw substrings: a
    # real logo.png orphan is masked by osi-logo.png under a substring match.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<img src="/osi-logo.png">')
        _png(root, 'osi-logo.png')
        _png(root, 'logo.png')
        fails = _assets_failures(check_site, root)
        check('logo.png masked by osi-logo.png is flagged',
              any('logo.png' in f and 'osi-logo.png' not in f for f in fails),
              repr(fails))
        check('referenced osi-logo.png not flagged',
              not any('osi-logo.png' in f for f in fails), repr(fails))

    # check_image_format: a CONTENT raster reference must be webp; og:image /
    # favicon may stay PNG; the static allowlist exempts a basename.
    _page = ('<!doctype html><html><head><title>t</title></head>'
             '<body>%s</body></html>')

    def _fmt_failures(root):
        failures = []
        check_site.check_image_format(root, failures)
        return failures

    # 8. content .png flagged; .webp passes (the both-way canary).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % '<img src="/demo.png">')
        check('content .png flagged',
              any('demo.png' in f for f in _fmt_failures(root)))
        _write(root, 'index.html', _page % '<img src="/demo.webp">')
        check('content .webp passes', _fmt_failures(root) == [])

    # 9. <a href> to a raster and inline CSS url() are content references too.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % '<a href="/full.jpg">x</a>')
        check('<a href> raster flagged',
              any('full.jpg' in f for f in _fmt_failures(root)))
        _write(root, 'index.html',
               _page % '<div style="background:url(/bg.png)">x</div>')
        check('inline css url() raster flagged',
              any('bg.png' in f for f in _fmt_failures(root)))

    # 10. og:image / twitter:image / favicon are metadata, not content loads --
    # they may stay PNG/JPEG for social-scraper compatibility.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % (
            '<meta property="og:image" content="https://x.github.io/og.png">'
            '<meta name="twitter:image" content="https://x.github.io/og.png">'
            '<link rel="icon" href="/favicon.png">'))
        check('og:image + favicon may stay PNG', _fmt_failures(root) == [],
              repr(_fmt_failures(root)))

    # 11. STATIC_IMAGE_ALLOWLIST exempts a basename.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % '<img src="/gnu-logo.png">')
        saved = check_site.STATIC_IMAGE_ALLOWLIST
        try:
            check_site.STATIC_IMAGE_ALLOWLIST = frozenset({'gnu-logo.png'})
            check('allowlisted raster exempt', _fmt_failures(root) == [])
        finally:
            check_site.STATIC_IMAGE_ALLOWLIST = saved

    # 12. html_files() treats a .html with a same-name .webp sibling as a render
    # source (skips it) -- the fix that keeps a converted logo-wide.html from
    # being page-checked.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'logo-wide.html', '<html><body>render source</body></html>')
        _png(root, 'logo-wide.webp')   # presence of the sibling is what matters
        pages = set(check_site.html_files(root))
        check('.html with .webp sibling skipped',
              os.path.join(root, 'logo-wide.html') not in pages)
        os.remove(os.path.join(root, 'logo-wide.webp'))
        pages = set(check_site.html_files(root))
        check('.html with no image sibling is a page',
              os.path.join(root, 'logo-wide.html') in pages)

    # 13. The format gate must be WIRED into main(): a check that is defined but
    # never called silently enforces nothing (it shipped that way once).
    with open(os.path.join(_HERE, 'check_site.py'), encoding='utf-8') as handle:
        source = handle.read()
    main_body = source[source.index('def main('):]
    check('check_image_format is invoked from main()',
          'check_image_format(root, failures)' in main_body)

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        status = 'pass' if ok else 'FAIL'
        line = 'check_site_test: %s %s' % (status, name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_site_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
