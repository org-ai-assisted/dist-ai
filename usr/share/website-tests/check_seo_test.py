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

import inspect
import os
import sys
import tempfile
import unittest.mock
import xml.etree.ElementTree


def _load_check_site():
    # the static checks live in the importable core; import it (its real home) so a
    # test that monkeypatches a module global patches the dict the functions read.
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import site
    return site


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


def _page(canonical=None, noindex=False, refresh=None):
    # A content page as the generators emit it: a self-canonical indexable page
    # carries <link rel=canonical> to its OWN url; a redirect stub points canonical
    # (+ meta refresh) at ANOTHER url; a utility page is robots-noindex. `canonical`
    # is the href (absolute or root-relative); None omits the link (a 404/Category
    # stub). Coverage keys off these intrinsic signals, so tests must set them.
    out = ['<!doctype html>\n<html lang="en">\n']
    if noindex:
        out.append('<meta name="robots" content="noindex,nofollow">\n')
    if refresh:
        out.append('<meta http-equiv="refresh" content="0; url=%s">\n' % refresh)
    if canonical:
        out.append('<link rel="canonical" href="%s">\n' % canonical)
    out.append('<header class="nav"></header>\n')
    return ''.join(out)


def _seed(root, host):
    # A minimal but realistic multi-page site whose derived files are current.
    _write(root, 'index.html', _index(host))
    # A real indexable sub-page is self-canonical (coverage requires that).
    _write(root, 'sub/index.html', _page(canonical='https://%s/sub/' % host))
    with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
        h.write(cs.render_sitemap(root, host))
    with open(os.path.join(root, 'robots.txt'), 'w', encoding='utf-8') as h:
        h.write(cs.render_robots(host))
    _write(root, 'favicon.svg', '<svg xmlns="http://www.w3.org/2000/svg"/>')


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

    # check_seo: a sitemap that does NOT cover every indexable page is flagged (coverage,
    # not byte-identity -- any generator's sitemap passes as long as it lists the pages).
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), encoding='utf-8') as h:
            _sm = h.read()
        _sm = '\n'.join(ln for ln in _sm.splitlines() if '/sub/' not in ln) + '\n'
        with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
            h.write(_sm)
        check('a sitemap missing an indexable page is flagged',
              any('does not list' in p and '/sub/' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))
        # byte-level drift that still COVERS every page is NOT flagged (generic)
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), 'a', encoding='utf-8') as h:
            h.write('<!-- reformatted by another generator -->\n')
        check('a covering-but-reformatted sitemap is accepted',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))
        # coverage is by <loc> VALUE, not substring: a page whose URL appears only in a comment
        # (or only as a prefix of another <loc>) is NOT counted -- it is flagged.
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
            h.write('<?xml version="1.0"?><urlset>'
                    '<url><loc>https://%s/sub/</loc></url>'
                    '<!-- https://%s/ -->'
                    '</urlset>\n' % (host, host))
        _probs = cs.check_seo(root)
        check('home URL present only in a comment/prefix is flagged (not substring-matched)',
              any('does not list' in p and p.rstrip().endswith('/') for p in _probs),
              repr(_probs))
        # a COMMENTED-OUT <loc> element does not cover its page: XML parsing sees a comment
        # node, not a <loc>, so the page is flagged (a raw regex over the text would false-pass).
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
            h.write('<?xml version="1.0"?><urlset>'
                    '<url><loc>https://%s/sub/</loc></url>'
                    '<!-- <url><loc>https://%s/</loc></url> -->'
                    '</urlset>\n' % (host, host))
        _probs = cs.check_seo(root)
        check('a page covered only by a commented-out <loc> element is flagged',
              any('does not list' in p and p.rstrip().endswith('/') for p in _probs),
              repr(_probs))
        # a malformed sitemap is a real SEO defect, reported (not silently skipped)
        _seed(root, host)
        with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
            h.write('<urlset><url><loc>https://%s/</loc></url>' % host)  # unclosed urlset
        check('a malformed sitemap.xml is flagged',
              any('not well-formed XML' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))
        # an existing-but-UNREADABLE sitemap.xml is reported, not crashed-on: os.path.isfile
        # is True for a file open() cannot read (EACCES/EIO), so the read must wrap OSError
        # like every other artifact read here. Denied uid-independently (chmod 000 does not
        # stop CI root) by failing open() for the sitemap path only and delegating otherwise.
        _seed(root, host)
        sitemap_path = os.path.join(root, 'sitemap.xml')
        real_open = open

        def _deny_sitemap(path, *args, **kwargs):
            if os.path.abspath(path) == os.path.abspath(sitemap_path):
                raise PermissionError(13, 'Permission denied')
            return real_open(path, *args, **kwargs)
        crashed = False
        with unittest.mock.patch('builtins.open', _deny_sitemap):
            try:
                _probs = cs.check_seo(root)
            except OSError:
                crashed = True
                _probs = []
        check('an unreadable sitemap.xml is reported, not crashed-on',
              not crashed and any('unreadable' in p for p in _probs), repr(_probs))

    # check_seo: coverage REQUIRES only canonical + indexable CONTENT pages, mirroring
    # the generator's own sitemap inclusion rule from the page side. A built tree also
    # holds pages a correct sitemap OMITS; requiring them false-failed every one (the
    # real #262 deploy-blocker: 3061/3929 bogus does-not-list across both wiki sites).
    # Each class is judged by an INTRINSIC signal, with NO namespace knowledge -- so the
    # generator alone decides a page's fate (noindex it, or emit it self-canonical +
    # sitemapped) and coverage matches. This is key for the Special: namespace: a
    # transient Special page (Search/WhatLinksHere/RecentChanges) is noindex -> excluded,
    # while a Special page the generator chooses to index (a stable list page) is
    # self-canonical -> REQUIRED, exactly like any content page. Exclusion classes:
    #   - noindex (robots meta)             - Template:/File:, transient Special:, preview
    #   - redirect/alias (canonical->other) - redirect stubs; target is the real entry
    #   - no <link rel=canonical>           - 404, wiki Category: stubs
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'wiki/Real_Page.html',
               _page(canonical='https://%s/wiki/Real_Page' % host))
        _write(root, 'wiki/Noindex_Page.html',
               _page(canonical='https://%s/wiki/Noindex_Page' % host, noindex=True))
        _write(root, 'wiki/Redirect_Page.html',
               _page(canonical='https://%s/wiki/Real_Page' % host,
                     refresh='/wiki/Real_Page'))
        # A transient Special page the generator noindexes -> excluded via the robots rule,
        # NOT via any Special-name knowledge.
        _write(root, 'wiki/Special:Search.html',
               _page(canonical='https://%s/wiki/Special:Search' % host, noindex=True))
        # A Special page the generator indexes (self-canonical) -> required, like content.
        _write(root, 'wiki/Special:AllPages.html',
               _page(canonical='https://%s/wiki/Special:AllPages' % host))
        _write(root, 'wiki/Category:Foo.html', _page())  # no canonical (a stub)
        _write(root, 'robots.txt', cs.render_robots(host))
        # The CORRECT generator sitemap lists every canonical indexable page -- the two
        # content pages AND the indexed Special page; nothing else.
        _sm = ('<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url>'
               '<url><loc>https://%s/wiki/Real_Page</loc></url>'
               '<url><loc>https://%s/wiki/Special:AllPages</loc></url>'
               '</urlset>\n' % (host, host, host))
        _write(root, 'sitemap.xml', _sm)
        _probs = cs.check_seo(root)
        check('a realistic wiki tree: only canonical+indexable content is required',
              _probs == [], repr(_probs))
        # The excluded classes must never be demanded, even now that their pages exist.
        for _excl in ('Noindex_Page', 'Redirect_Page', 'Special:Search', 'Category'):
            check('coverage does not require the %s page' % _excl,
                  not any('does not list' in p and _excl in p for p in cs.check_seo(root)),
                  repr([p for p in cs.check_seo(root) if _excl in p]))
        # An INDEXED Special page IS required: drop it from the sitemap -> flagged.
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url>'
               '<url><loc>https://%s/wiki/Real_Page</loc></url></urlset>\n' % (host, host))
        check('an indexed Special page absent from the sitemap fails loud',
              any('does not list' in p and 'Special%3AAllPages' in p
                  for p in cs.check_seo(root)), repr(cs.check_seo(root)))
        _write(root, 'sitemap.xml', _sm)  # restore the correct sitemap
        # A genuinely-missing indexable content page STILL fails loud.
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url></urlset>\n' % host)
        check('a missing indexable content page still fails loud',
              any('does not list' in p and 'Real_Page' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))
        # An alias/redirect-only sitemap (lists the stub, not the target) does NOT
        # satisfy the target: the stub is not required, the target still is.
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url>'
               '<url><loc>https://%s/wiki/Redirect_Page</loc></url></urlset>\n'
               % (host, host))
        check('a redirect-stub loc does not satisfy the canonical target',
              any('does not list' in p and 'Real_Page' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: a clean-URL (extensionless) sitemap COVERS an X.html built tree. A
    # clean-URL static server (GitHub Pages, the wiki generator's nginx try_files
    # <uri> else <uri>.html) serves wiki/AEM.html at the canonical /wiki/AEM, so the
    # generator's sitemap lists the extensionless form while the tree holds X.html.
    # Both that form and the '.html'-terminal form (dist-ai's own render_sitemap) pass.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'wiki/AEM.html',
               _page(canonical='https://%s/wiki/AEM' % host))
        _write(root, 'robots.txt', cs.render_robots(host))
        for _form in ('https://%s/wiki/AEM' % host, 'https://%s/wiki/AEM.html' % host):
            _write(root, 'sitemap.xml',
                   '<?xml version="1.0"?><urlset>'
                   '<url><loc>https://%s/</loc></url>'
                   '<url><loc>%s</loc></url></urlset>\n' % (host, _form))
            check('sitemap form %r covers the built AEM.html' % _form,
                  cs.check_seo(root) == [], repr(cs.check_seo(root)))
        # Neither form present -> still flagged.
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url></urlset>\n' % host)
        check('a clean-URL sitemap still flags a truly missing page',
              any('does not list' in p and 'AEM' in p for p in cs.check_seo(root)),
              repr(cs.check_seo(root)))

    # check_seo: clean-URL tolerance respects server shadowing. With BOTH a.html and
    # a.html.html built, the server serves /a.html as the real a.html file -- so
    # /a.html does NOT cover a.html.html (only served at /a.html.html). A sitemap
    # listing only / and /a.html must FLAG a.html.html (a blind .html-strip would not).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'a.html', _page(canonical='https://%s/a.html' % host))
        _write(root, 'a.html.html', _page(canonical='https://%s/a.html.html' % host))
        _write(root, 'robots.txt', cs.render_robots(host))
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url>'
               '<url><loc>https://%s/a.html</loc></url></urlset>\n' % (host, host))
        _probs = cs.check_seo(root)
        check('a shadowed extensionless form does not vouch for a.html.html',
              any('does not list' in p and p.endswith('/a.html.html')
                  for p in _probs), repr(_probs))
        check('the real a.html IS covered by its own /a.html <loc>',
              not any('does not list' in p and p.rstrip().endswith('/a.html')
                      for p in _probs), repr(_probs))
        # Unshadowed: drop a.html -> /a.html is now a.html.html's genuine clean form.
        os.remove(os.path.join(root, 'a.html'))
        check('an unshadowed /a.html clean form covers a.html.html',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # check_seo: a same-named DIRECTORY does NOT shadow the extensionless form. The
    # wiki emits both wiki/KVM.html and a wiki/KVM/ subpage dir; the server serves
    # /wiki/KVM as wiki/KVM.html (.html wins over the dir), so a sitemap listing
    # /wiki/KVM (+ /wiki/KVM/Child) correctly covers both.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _index(host))
        _write(root, 'wiki/KVM.html', _page(canonical='https://%s/wiki/KVM' % host))
        _write(root, 'wiki/KVM/Child.html',
               _page(canonical='https://%s/wiki/KVM/Child' % host))
        _write(root, 'robots.txt', cs.render_robots(host))
        _write(root, 'sitemap.xml',
               '<?xml version="1.0"?><urlset>'
               '<url><loc>https://%s/</loc></url>'
               '<url><loc>https://%s/wiki/KVM</loc></url>'
               '<url><loc>https://%s/wiki/KVM/Child</loc></url></urlset>\n'
               % (host, host, host))
        check('a same-named subpage dir does not shadow /wiki/KVM',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # _page_served_paths: the extensionless clean-URL form is added only for a REAL
    # page stem. An empty stem ('.html' -> '', 'sub/.html' -> 'sub/') or a dot stem
    # ('..html' -> '.', '...html' -> '..') would collapse the clean URL onto a
    # directory/root path, so it is NEVER synthesized -- else the index's '/' <loc>
    # could vouch for the page. A normal stem keeps both served forms.
    with tempfile.TemporaryDirectory() as root:
        for _rel, _want in (('.html', {'/.html'}),
                            ('sub/.html', {'/sub/.html'}),
                            ('..html', {'/..html'}),
                            ('...html', {'/...html'}),
                            ('wiki/AEM.html', {'/wiki/AEM.html', '/wiki/AEM'})):
            check('_page_served_paths(%r) omits a collapsed form' % _rel,
                  cs._page_served_paths(root, _rel) == _want,
                  repr(cs._page_served_paths(root, _rel)))

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

    # check_seo: a favicon is OPTIONAL -- site-generate emits one only when the source ships
    # favicon.svg and returns 0 without one, so --check must NOT reject a favicon-less site
    # (generate/check symmetry; a required-favicon rule here broke the csr --check gate). A
    # present favicon in any form is of course also fine.
    with tempfile.TemporaryDirectory() as root:
        _seed(root, host)
        os.remove(os.path.join(root, 'favicon.svg'))
        check('a site with NO favicon is not flagged (favicon optional)',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))
        _png(root, 'favicon.png', 16, 16)
        check('a site WITH a favicon is also accepted',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # check_seo: a non-site directory is skipped
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'notes.txt', 'no index here')
        check('a directory with no index.html is not a site root',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))

    # check_seo: a temporarily-no-index site (every page carries a noindex meta,
    # an interim host) still advertises its real pages -- robots Allows crawling
    # and the sitemap LISTS the pages; the per-page noindex meta, not robots,
    # keeps them out of indexes. So the sitemap is populated, not empty.
    with tempfile.TemporaryDirectory() as root:
        noindex = ('<!doctype html>\n<html lang="en">\n'
                   '<meta name="robots" content="noindex">\n'
                   '<link rel="canonical" href="https://%s/">\n'
                   '<header class="nav"></header>\n' % host)
        _write(root, 'index.html', noindex)
        _write(root, 'sub/index.html',
               '<meta name="robots" content="noindex">'
               '<header class="nav"></header>')
        with open(os.path.join(root, 'sitemap.xml'), 'w', encoding='utf-8') as h:
            h.write(cs.render_sitemap(root, host))
        with open(os.path.join(root, 'robots.txt'), 'w', encoding='utf-8') as h:
            h.write(cs.render_robots(host, no_index=True))
        _write(root, 'favicon.svg', '<svg xmlns="http://www.w3.org/2000/svg"/>')
        check('a no-index site is clean (sitemap optional, robots + favicon present)',
              cs.check_seo(root) == [], repr(cs.check_seo(root)))
        check('the no-index site sitemap lists its noindex pages',
              cs.render_sitemap(root, host).count('<loc>') == 2,
              repr(cs.render_sitemap(root, host)))
        check('no-index robots Disallows PDFs (no meta/X-Robots-Tag possible)',
              'Disallow: /*.pdf$' in cs.render_robots(host, no_index=True),
              repr(cs.render_robots(host, no_index=True)))
        check('no-index robots Disallows the LaTeX source (.tex)',
              'Disallow: /*.tex$' in cs.render_robots(host, no_index=True),
              repr(cs.render_robots(host, no_index=True)))
        check('no-index robots Disallows the .bib bibliography',
              'Disallow: /*.bib$' in cs.render_robots(host, no_index=True),
              repr(cs.render_robots(host, no_index=True)))
        # The csr previews policy serves a Word manuscript, so its robots adds a
        # docx Disallow on top of pdf/tex/bib; the default (family/wiki) set does
        # NOT -- keeping those sites' robots.txt byte-identical.
        csr_exts = ('pdf', 'tex', 'bib', 'docx')
        check('csr robots Disallows the Word manuscript (.docx)',
              'Disallow: /*.docx$' in cs.render_robots(
                  host, no_index=True, artifact_exts=csr_exts),
              repr(cs.render_robots(host, no_index=True, artifact_exts=csr_exts)))
        check('default (family/wiki) robots does NOT Disallow .docx',
              'Disallow: /*.docx$' not in cs.render_robots(host, no_index=True),
              repr(cs.render_robots(host, no_index=True)))

    # _site_no_index detects the noindex directive GENERICALLY (extra directives + attribute
    # order), so the indexable-site sitemap requirement is not falsely imposed on a no-index
    # build whose meta reads content="noindex,nofollow" (a real wiki stage build).
    for _frag, _want, _label in (
            ('<meta name="robots" content="noindex,nofollow">', True, 'noindex,nofollow'),
            ('<meta content="noindex" name="robots">', True, 'content-before-name'),
            ('<meta name="robots" content="index,follow">', False, 'index,follow'),
            ('', False, 'no robots meta'),
            ('<!-- <meta name="robots" content="noindex"> -->', False, 'noindex in a comment'),
            ('<meta data-content="noindex" name="robots" content="index,follow">',
             False, 'data-content decoy (real content is index)'),
            ('<meta name="robots" content="noindexable">', False, 'noindexable != noindex token'),
            ('<meta name=robots content=noindex>', True, 'unquoted noindex'),
            ('<script>var x="<meta name=\'robots\' content=\'noindex\'>";</script>',
             False, 'noindex only in script text')):
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html',
                   '%s<link rel="canonical" href="https://h/">' % _frag)
            check('_site_no_index: %s -> %s' % (_label, _want),
                  cs._site_no_index(root) == _want, repr(cs._site_no_index(root)))

    # the gate must be wired into main() -- read the real function source wherever
    # it lives (the core module), not a fixed file path, so the CLI-shim split does
    # not blind this guard.
    main_src = inspect.getsource(cs.main)
    check('check_seo_current invoked from main() with the per-root policy',
          'check_seo_current(root, failures, policy)' in main_src)

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
