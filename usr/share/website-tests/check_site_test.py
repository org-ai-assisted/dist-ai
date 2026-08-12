#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_site.py's orphaned-image guard (check_assets).

Fails on the pre-guard check_site.py: check_assets does not exist there, so the
import below raises AttributeError -- the guard cannot silently regress away.

Canary cases (would pass a naive HTML-only implementation only by accident):
 - a logo referenced ONLY from README.md must NOT be flagged (the real
   false-positive found in output-lies.github.io);
 - a background referenced ONLY from a CSS url() must NOT be flagged;
 - an image named by nothing MUST be flagged.

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
