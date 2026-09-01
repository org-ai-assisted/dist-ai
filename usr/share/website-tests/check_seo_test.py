#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test for check_site.py's SEO artifacts: host derivation, the
sitemap/robots renderers, the PNG size probe, and the check_seo drift gate.

Fails on a pre-guard check_site.py: check_seo does not exist there, so the
getattr below raises AttributeError -- the gate cannot silently regress away.

Canary cases (a naive implementation trips at least one):
 - a render-source page (a .html with a same-basename image sibling) must NOT
   appear in the sitemap, the same exclusion html_files applies;
 - a nested index maps to its DIRECTORY url ('/sub/'), not '/sub/index.html';
 - a sitemap that lists a stale/extra/missing url MUST be flagged;
 - a missing <link rel=canonical> MUST be flagged (host cannot be derived);
 - favicon.svg present but favicon.png missing / wrong-size MUST be flagged,
   while a correct 512x512 favicon.png must NOT;
 - a directory with no index.html is not a site root -> no failures.

Pure standard library, no network. Run directly: ./check_seo_test.py
"""

import importlib.util
import os
import sys
import tempfile
import xml.etree.ElementTree

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_check_site():
    spec = importlib.util.spec_from_file_location(
        'check_site', os.path.join(_HERE, 'check_site.py'))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cs = _load_check_site()


def _write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)


def _png(root, rel, width, height, complete=True):
    # PNG signature + a well-formed IHDR carrying the size, optionally closed by
    # the IEND chunk. _png_size reads the 24-byte head; _png_complete checks the
    # trailing IEND, so complete=False yields a genuinely truncated file.
    data = (cs._PNG_MAGIC + cs._PNG_IHDR_LEN + b'IHDR'
            + width.to_bytes(4, 'big') + height.to_bytes(4, 'big'))
    if complete:
        data += cs._PNG_IEND
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(data)


def _index(host):
    return ('<!doctype html>\n<html lang="en">\n'
            '<link rel="canonical" href="https://%s/">\n'
            '<header class="nav"></header>\n' % host)


def _seed(root, host):
    # A minimal but realistic multi-page site whose derived files are current.
    _write(root, 'index.html', _index(host))
    _write(root, 'sub/index.html', '<header class="nav"></header>')
    with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
        h.write(cs.render_sitemap(root, host))
    with open(os.path.join(root, 'robots.txt'), 'w', encoding='utf-8') as h:
        h.write(cs.render_robots(host))


results = []


def check(name, ok, detail=''):
    results.append((name, bool(ok), detail))


def run():
    host = 'example.github.io'

    # host derivation
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        check('seo_host reads the canonical host',
              cs.seo_host(root) == host, repr(cs.seo_host(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<header></header>')
        check('seo_host is None without a canonical link',
              cs.seo_host(root) is None, repr(cs.seo_host(root)))
    with tempfile.TemporaryDirectory() as root:
        # HTML attribute order is insignificant: href before rel must still parse.
        _write(root, 'index.html',
               '<link href="https://%s/" rel="canonical">' % host)
        check('seo_host parses with href before rel',
              cs.seo_host(root) == host, repr(cs.seo_host(root)))
    with tempfile.TemporaryDirectory() as root:
        # A multi-token rel ('alternate canonical') still carries canonical.
        _write(root, 'index.html',
               '<link rel="alternate canonical" href="https://%s/">' % host)
        check('seo_host honors a multi-token rel',
              cs.seo_host(root) == host, repr(cs.seo_host(root)))
    with tempfile.TemporaryDirectory() as root:
        # A canonical inside an HTML comment is not a live tag -> ignored.
        _write(root, 'index.html',
               '<!-- <link rel="canonical" href="https://evil.example/"> -->')
        check('seo_host ignores a commented-out canonical',
              cs.seo_host(root) is None, repr(cs.seo_host(root)))

    # page-url mapping + render-source exclusion
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'sub/index.html', '<p>x</p>')
        # og.html is a render source (og.png sibling) -> excluded from urls
        _write(root, 'og.html', '<p>render source</p>')
        _png(root, 'og.png', 1200, 630)
        urls = cs.seo_page_urls(root, host)
        check('nested index maps to its directory url',
              'https://%s/sub/' % host in urls, repr(urls))
        check('home maps to /',
              'https://%s/' % host in urls, repr(urls))
        check('render-source .html is excluded from the sitemap',
              not any('og' in u for u in urls), repr(urls))
        check('urls are sorted',
              urls == sorted(urls), repr(urls))
        # The sitemap must actually EMIT a <loc> per page -- a self-consistent
        # write/check pair would miss a renderer that drops every url.
        sitemap = cs.render_sitemap(root, host)
        check('sitemap emits a <loc> for each content page',
              ('<loc>https://%s/sub/</loc>' % host) in sitemap
              and ('<loc>https://%s/</loc>' % host) in sitemap, repr(sitemap))
        check('sitemap has one <loc> per url and no render source',
              sitemap.count('<loc>') == len(urls) and '/og' not in sitemap,
              repr(sitemap))

    # renderer shape
    check('sitemap has the xml decl + urlset namespace',
          cs.render_sitemap.__doc__ is not None
          and cs.render_sitemap(tempfile.mkdtemp(), host).startswith(
              '<?xml version="1.0" encoding="UTF-8"?>\n'
              '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'))
    robots = cs.render_robots(host)
    check('robots names the per-host sitemap',
          'Sitemap: https://%s/sitemap.xml\n' % host in robots, repr(robots))

    # A legal filename with XML/URL metacharacters must be percent-encoded and
    # the sitemap must stay well-formed XML (parseable, no raw '&').
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'a&b.html', '<p>x</p>')
        sitemap = cs.render_sitemap(root, host)
        parsed_ok = True
        try:
            # nosec B314 -- parses our OWN render_sitemap output (a well-formedness
            # assertion), not untrusted input; defusedxml is not warranted here.
            xml.etree.ElementTree.fromstring(sitemap)  # nosec
        except xml.etree.ElementTree.ParseError:
            parsed_ok = False
        check('sitemap with a metachar filename is well-formed XML',
              parsed_ok, repr(sitemap))
        check('metachar filename is percent-encoded in the sitemap',
              'a%26b.html' in sitemap and 'a&b.html' not in sitemap,
              repr(sitemap))

    # _png_size
    with tempfile.TemporaryDirectory() as root:
        _png(root, 'a.png', 512, 512)
        check('_png_size reads IHDR dimensions',
              cs._png_size(os.path.join(root, 'a.png')) == (512, 512),
              repr(cs._png_size(os.path.join(root, 'a.png'))))
        _write(root, 'b.png', 'not a png')
        check('_png_size is None for a non-PNG',
              cs._png_size(os.path.join(root, 'b.png')) is None)
        _png(root, 'c.png', 512, 512, complete=False)
        check('_png_complete is False for a truncated PNG',
              not cs._png_complete(os.path.join(root, 'c.png')))
        check('_png_complete is True for a closed PNG',
              cs._png_complete(os.path.join(root, 'a.png')))
        with open(os.path.join(root, 'd.png'), 'wb') as handle:
            handle.write(cs._PNG_MAGIC + b'\x00\x00\x00\x09IHDR'
                         + (512).to_bytes(4, 'big') + (512).to_bytes(4, 'big'))
        check('_png_size rejects a bad IHDR length',
              cs._png_size(os.path.join(root, 'd.png')) is None)

    # check_seo: clean site
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        check('current site has no SEO problems',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # check_seo: stale sitemap
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), 'a', encoding='utf-8') as h:
            h.write('<extra/>\n')
        check('a stale sitemap is flagged',
              any('sitemap.xml stale' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: missing sitemap
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        os.remove(os.path.join(root, 'sitemap.xml'))
        check('a missing sitemap is flagged',
              any('sitemap.xml missing' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: missing canonical
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<header></header>')
        check('a missing canonical is flagged',
              any('canonical' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: favicon presence/size
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        _write(root, 'favicon.svg', '<svg/>')
        check('favicon.svg without favicon.png is flagged',
              any('favicon.png missing' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))
        _png(root, 'favicon.png', 256, 256)
        check('a wrong-size favicon.png is flagged',
              any('favicon.png is 256x256' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))
        _png(root, 'favicon.png', cs.FAVICON_SIZE, cs.FAVICON_SIZE)
        check('a correct-size favicon.png is clean',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))
        _png(root, 'favicon.png', cs.FAVICON_SIZE, cs.FAVICON_SIZE,
             complete=False)
        check('a truncated favicon.png is flagged',
              any('truncated' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: a non-site directory is skipped
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'notes.txt', 'no index here')
        check('a directory with no index.html is not a site root',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # the gate must be wired into main()
    with open(os.path.join(_HERE, 'check_site.py'), encoding='utf-8') as handle:
        main_src = handle.read()
    check('check_seo_current invoked from main()',
          'check_seo_current(root, failures)' in main_src)

    passed = sum(1 for _n, ok, _d in results if ok)
    failed = len(results) - passed
    for name, ok, detail in results:
        status = 'pass' if ok else 'FAIL'
        line = 'check_seo_test: %s %s' % (status, name)
        if not ok and detail:
            line += ' -- got %s' % detail
        (sys.stdout if ok else sys.stderr).write(line + '\n')
    sys.stdout.write('check_seo_test: %d pass, %d fail, 0 skip\n'
                     % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(run())
