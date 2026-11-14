#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_site.py's og:image social-preview gate (check_og_image):
every served wiki page (regular + Special:* + File:*) must carry an og:image whose
file resolves in the built tree, and a GENERATED card (/media/cards/) must also carry
og:image:width/height.

Fails on a pre-guard check_site.py: check_og_image does not exist there, so the
getattr below raises AttributeError -- the gate cannot silently regress away. The
wiki-policy wiring in main() is asserted from the live function source.

Canary cases (a naive implementation trips at least one):
 - a page with NO og:image MUST be flagged (special pages regressed here);
 - an og:image URL that resolves to no file in the tree MUST be flagged;
 - a generated card WITHOUT og:image:width/height MUST be flagged, while the SAME
   card WITH the dims must NOT;
 - a File: page's own-image og:image (no dims) resolving MUST pass (dims are only
   required for a generated card);
 - a redirect stub (<meta http-equiv=refresh; url=...>) with no og:image is EXEMPT;
 - a page whose og:image appears only in the <body> is NOT satisfied (head-only);
 - the ephemeral test-results plane is exempt;
 - an og:image with a '..' traversal cannot escape the checkout.

Pure standard library, no network. Run directly: ./check_og_image_test.py
"""

import inspect
import os
import sys
import tempfile


def _load_check_site():
    # the static checks live in the importable core; import it (its real home) so the
    # test drives the exact functions main() calls. Prepend this tree's dist-packages
    # (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import site
    return site


cs = _load_check_site()

_HOST = 'https://kicksecure-stage.github.io'


def _write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)


def _page(og=None, width=False, height=False, refresh=None, body_og=None):
    """A minimal valid-enough document: og:image (+ optional dims) in the head, or a
    refresh stub, or an og:image stranded in the body (must NOT satisfy the head check)."""
    head = []
    if refresh is not None:
        head.append('<meta http-equiv="refresh" content="%s">' % refresh)
    if og is not None:
        head.append('<meta property="og:image" content="%s">' % og)
    if width:
        head.append('<meta property="og:image:width" content="1200">')
    if height:
        head.append('<meta property="og:image:height" content="630">')
    body = '<h1>x</h1>'
    if body_og is not None:
        body += '<meta property="og:image" content="%s">' % body_og
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">%s</head>'
            '<body>%s</body></html>' % (''.join(head), body))


def _fails(root):
    f = []
    cs.check_og_image(root, f)
    return f


results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))


def run():
    # the gate must EXIST (AttributeError on a pre-guard check_site.py -> the test cannot
    # pass silently) and be wired into main() under the wiki policy.
    check('check_og_image exists', hasattr(cs, 'check_og_image'))
    main_src = inspect.getsource(cs.main)
    check('check_og_image invoked from main()', 'check_og_image(root, failures)' in main_src)

    # a complete page: a generated card with dims, card file present -> clean.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/cards/wiki-Tor-abc.jpg', 'JPEGBYTES')
        _write(root, 'wiki/Tor.html',
               _page(og=_HOST + '/media/cards/wiki-Tor-abc.jpg', width=True, height=True))
        f = _fails(root)
        check('a card page with dims + a present file is clean', f == [], repr(f))

    # a File: page: og:image is the actual media (original format), no dims -> clean (dims
    # are only required for a generated card).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/orig/Testpic.png', 'PNGBYTES')
        _write(root, 'wiki/File:Testpic.png.html',
               _page(og=_HOST + '/media/orig/Testpic.png'))
        f = _fails(root)
        check('a File: page image (no dims) that resolves is clean', f == [], repr(f))

    # a page MISSING og:image -> flagged (the special-page regression).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'wiki/Special:AllPages.html', _page(og=None))
        f = _fails(root)
        check('a page with no og:image is flagged',
              len(f) == 1 and 'missing' in f[0], repr(f))

    # an og:image pointing at a MISSING file -> flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'wiki/Ghost.html',
               _page(og=_HOST + '/media/cards/not-built.jpg', width=True, height=True))
        f = _fails(root)
        check('an og:image resolving to no file is flagged',
              len(f) == 1 and 'does not resolve' in f[0], repr(f))

    # a generated card WITHOUT dims -> flagged; the SAME card WITH dims -> clean.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/cards/wiki-Foo-xyz.jpg', 'JPEGBYTES')
        _write(root, 'wiki/NoDims.html', _page(og=_HOST + '/media/cards/wiki-Foo-xyz.jpg'))
        f = _fails(root)
        check('a generated card without og:image:width/height is flagged',
              len(f) == 1 and 'without og:image:width/height' in f[0], repr(f))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/cards/wiki-Foo-xyz.jpg', 'JPEGBYTES')
        _write(root, 'wiki/WithDims.html',
               _page(og=_HOST + '/media/cards/wiki-Foo-xyz.jpg', width=True, height=True))
        check('the same card WITH dims is clean', _fails(root) == [])

    # a redirect stub (refresh naming a target) with no og:image -> EXEMPT.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'wiki/Old.html', _page(og=None, refresh='0; url=/wiki/New'))
        check('a redirect stub without og:image is exempt', _fails(root) == [])

    # a BARE-delay refresh is NOT a redirect stub -> a real page, still must carry og:image.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'wiki/Reload.html', _page(og=None, refresh='30'))
        f = _fails(root)
        check('a bare-delay refresh page is not exempt (still needs og:image)',
              len(f) == 1 and 'missing' in f[0], repr(f))

    # og:image only in the BODY does not satisfy the head check.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/cards/c.jpg', 'J')
        _write(root, 'wiki/BodyOnly.html',
               _page(og=None, body_og=_HOST + '/media/cards/c.jpg'))
        f = _fails(root)
        check('an og:image only in <body> does not satisfy the head check',
              len(f) == 1 and 'missing' in f[0], repr(f))

    # the ephemeral results plane is exempt.
    with tempfile.TemporaryDirectory() as root:
        _write(root, os.path.join(cs.RESULTS_SUBDIR, 'index.html'), _page(og=None))
        check('the results plane is exempt from og:image', _fails(root) == [])

    # a root-absolute og:image (no host) resolves against the tree root too.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/orig/Pic.png', 'P')
        _write(root, 'wiki/RootAbs.html', _page(og='/media/orig/Pic.png'))
        check('a root-absolute og:image resolves', _fails(root) == [])

    # a '..' traversal in the og:image cannot escape the checkout -> treated as unresolved
    # (never reaches a real file outside root), so it is flagged, not silently passed.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'wiki/Escape.html',
               _page(og=_HOST + '/../../../../etc/hostname', width=True, height=True))
        f = _fails(root)
        check('a .. traversal og:image cannot escape the tree -> flagged',
              len(f) == 1 and 'does not resolve' in f[0], repr(f))

    # whole-tree enumeration: a tree with a clean regular page AND a special page missing
    # its card reports EXACTLY the one missing page (canary-red on today's generator).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'media/cards/wiki-Tor-abc.jpg', 'J')
        _write(root, 'wiki/Tor.html',
               _page(og=_HOST + '/media/cards/wiki-Tor-abc.jpg', width=True, height=True))
        _write(root, 'wiki/Special:RecentChanges.html', _page(og=None))
        f = _fails(root)
        check('full-tree scan flags exactly the one preview-less special page',
              len(f) == 1 and 'Special:RecentChanges.html' in f[0], repr(f))

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        status = 'pass' if ok else 'FAIL'
        line = 'check_og_image_test: %s %s' % (status, name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_og_image_test: %d pass, %d fail, 0 skip\n' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
