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
    failures: list[str] = []
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
        failures: list[str] = []
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
        # But url(...) inside a code sample / script is NOT a style -> not flagged.
        _write(root, 'index.html',
               _page % '<pre>body { background: url(/sample.png) }</pre>'
                       '<script>var s = "url(/scripted.png)";</script>')
        fails = _fmt_failures(root)
        check('url() in a code sample / script is not flagged',
              not any('sample.png' in f or 'scripted.png' in f for f in fails),
              repr(fails))

    # 9b. An EXTERNAL raster reference is not a site-served asset: it cannot be
    # webp-converted (supply-chain gates it instead), so it must NOT be flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % ('<a href="https://example.com/x.png">x</a>'
                        '<img src="https://example.com/y.png">'))
        check('external raster reference not flagged must-be-webp',
              _fmt_failures(root) == [], repr(_fmt_failures(root)))

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

    # check_heading_breaks: a hard <br> inside a heading is the mobile-orphan bug.
    def _hb_failures(root):
        failures: list[str] = []
        check_site.check_heading_breaks(root, failures)
        return failures

    # 14. A <br> inside an h1 is flagged; the same h1 without it passes. Both the
    # <br> and <br/> spellings count (the pre-fix sites used the bare form).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % '<h1>The text on your screen<br>can lie.</h1>')
        check('heading <br> flagged', any('heading' in f for f in _hb_failures(root)),
              repr(_hb_failures(root)))
        _write(root, 'index.html', _page % '<h1>The text on your screen<br/>can lie.</h1>')
        check('heading <br/> self-closing flagged', _hb_failures(root) != [])
        _write(root, 'index.html', _page % '<h1>The text on your screen can lie.</h1>')
        check('heading with no <br> passes', _hb_failures(root) == [])

    # 15. Canary: a <br> OUTSIDE a heading (body prose, a table cell) must NOT be
    # flagged -- the rule is heading-scoped, not a blanket "no <br>".
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<p>line one<br>line two</p>'
                       '<table><tr><td>a<br>b</td></tr></table>'
                       '<h2>clean heading</h2>')
        check('body / cell <br> not flagged', _hb_failures(root) == [],
              repr(_hb_failures(root)))

    # check_contrast: a token used as small text on --bg must clear WCAG AA.
    def _ct_failures(root):
        failures: list[str] = []
        check_site.check_contrast(root, failures)
        return failures

    # 16. A low-contrast accent used as text is flagged; a high-contrast one is
    # not (the both-way canary that proves the math runs, not a constant).
    with tempfile.TemporaryDirectory() as root:
        # #d83933 on #f3f2ee == 4.12:1 (below AA); #c21a74 == 5.08:1 (above).
        _write(root, 'index.html',
               _page % '<link rel="stylesheet" href="style.css">')
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:#d83933}.kicker{color:var(--accent)}')
        check('low-contrast accent flagged',
              any('--accent' in f and '4.12' in f for f in _ct_failures(root)),
              repr(_ct_failures(root)))
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:#c21a74}.kicker{color:var(--accent)}')
        check('high-contrast accent passes', _ct_failures(root) == [],
              repr(_ct_failures(root)))

    # 17. Canary: a token defined but used only as a BACKGROUND (never as text)
    # is not judged against --bg -- and the dark terminal palette (not in the
    # paper-text vocabulary) is never flagged even at low paper contrast.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<link rel="stylesheet" href="style.css">')
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:#d83933;--tfg:#727a8a}'
               '.pill{background:var(--accent)}'          # accent as bg only
               '.term{color:var(--tfg)}')                 # dark-palette text token
        check('background-only + dark-palette token not flagged',
              _ct_failures(root) == [], repr(_ct_failures(root)))

    # 17b. regression (reviewdrain3): a :root nested in @media (prefers-color-scheme:
    # dark) must NOT be merged into the default palette. Its dark --bg would otherwise
    # be contrast-paired with the un-overridden light --accent (a pairing that never
    # renders together) and falsely fail. Both-way canary so it is not a constant-pass:
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<link rel="stylesheet" href="style.css">')
        # light --accent passes on the light --bg (5.08:1); a dark-scheme :root overrides
        # only --bg. Pre-fix the flat merge paired that dark --bg with the light --accent
        # (#c21a74 on #111418 == 3.25:1) and falsely flagged it.
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:#c21a74}'
               '@media (prefers-color-scheme:dark){:root{--bg:#111418}}'
               '.kicker{color:var(--accent)}')
        check('a dark-scheme :root override does not cause a false contrast failure',
              _ct_failures(root) == [], repr(_ct_failures(root)))
        # canary: a nested dark :root must not SUPPRESS a real TOP-LEVEL failure either.
        # The top-level --accent is low-contrast on the light --bg (#d83933 == 4.12:1);
        # only the top-level fix reports exactly 4.12 (the flat merge would judge it on
        # the dark --bg and report a different ratio), so this is non-tautological.
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:#d83933}'
               '@media (prefers-color-scheme:dark){:root{--bg:#111418}}'
               '.kicker{color:var(--accent)}')
        check('a real top-level low-contrast is still flagged despite a dark :root block',
              any('--accent' in f and '4.12' in f for f in _ct_failures(root)),
              repr(_ct_failures(root)))

    # 18. Both new checks must be WIRED into main() (defined-but-uncalled = a
    # silent no-op, the exact regression case 13 guards for check_image_format).
    check('check_heading_breaks is invoked from main()',
          'check_heading_breaks(root, failures)' in main_body)
    check('check_contrast is invoked from main()',
          'check_contrast(root, failures)' in main_body)

    # check_banner: the status pill may be a <span> OR an <a> (it links to the
    # review-model explanation). Either form must still be text-checked -- a
    # <span>-only regex silently stopped validating once the pill became a link.
    def _banner_failures(markup):
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html', markup)
            failures: list[str] = []
            check_site.check_banner(root, failures)
            return failures

    check('<a> status pill saying review passes',
          _banner_failures(_page % '<a class="status" href="/x">unreviewed</a>') == [])
    check('<a> status pill NOT saying review is flagged',
          _banner_failures(_page % '<a class="status" href="/x">working</a>') != [])
    check('<span> status pill still text-checked',
          _banner_failures(_page % '<span class="status">shipping</span>') != [])

    # check_undefined_classes: a SOLE class defined nowhere renders unstyled (the
    # eyebrow bug); a co-class marker, an allowlisted hook, and a JS-referenced
    # class must NOT be flagged (keeps it low-noise).
    def _uc_failures(root):
        failures: list[str] = []
        check_site.check_undefined_classes(root, failures)
        return failures

    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % (
            '<style>.kicker{color:green}.cat{}</style>'
            '<p class="eyebrow">bad</p>'                    # sole + undefined -> flag
            '<p class="kicker">ok</p>'                      # sole + defined -> ok
            '<section class="cat faq">co</section>'))       # co-class marker -> ok
        fails = _uc_failures(root)
        check('sole undefined class flagged', any('eyebrow' in x for x in fails), repr(fails))
        check('defined sole class not flagged', not any("'kicker'" in x for x in fails), repr(fails))
        check('co-class marker not flagged', not any("'faq'" in x for x in fails), repr(fails))

    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % (
            '<div class="asplayer">p</div>'                 # allowlisted sole hook
            '<span class="jshook">j</span>'                 # referenced from JS
            # a whitespace-bearing end tag (</script >) must still be captured, or the JS
            # reference is missed and jshook is falsely flagged undefined (CodeQL py/bad-tag-filter).
            '<script>document.querySelector(".jshook")</script >'))
        fails = _uc_failures(root)
        check('allowlisted sole hook not flagged', not any('asplayer' in x for x in fails), repr(fails))
        check('JS-referenced sole class not flagged', not any('jshook' in x for x in fails), repr(fails))

    check('check_undefined_classes invoked from main()',
          'check_undefined_classes(root, failures)' in main_body)

    # check_csp: script-src must not permit inline execution. A page keeps
    # style-src 'unsafe-inline' (inline CSS is untouched) -- the check must read
    # the script-src directive alone, never the whole string.
    _csp = ("default-src 'none'; script-src %s; style-src 'self' 'unsafe-inline';"
            " img-src 'self' data:; base-uri 'none'; form-action 'none'")
    # Same, but %s is the WHOLE script-directive segment (for multi/duplicate
    # script directives), so the fixture stays a complete, valid CSP.
    _csp2 = ("default-src 'none'; %s; style-src 'self' 'unsafe-inline';"
             " img-src 'self' data:; base-uri 'none'; form-action 'none'")
    _cpage = ('<!doctype html><html><head><title>t</title>'
              '<meta http-equiv="Content-Security-Policy" content="%s">'
              '</head><body>%s</body></html>')

    def _csp_failures(root):
        failures: list[str] = []
        check_site.check_csp(root, failures)
        return failures

    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _cpage % (_csp % "'self' 'unsafe-inline'", ''))
        fails = _csp_failures(root)
        check('script-src unsafe-inline flagged',
              any('unsafe-inline' in f for f in fails), repr(fails))
    with tempfile.TemporaryDirectory() as root:
        # Strict script-src, but style-src STILL carries unsafe-inline: must pass
        # (the canary that the check does not scan the whole CSP string).
        _write(root, 'index.html', _cpage % (_csp % "'self'", ''))
        check('strict script-src (with inline style) passes',
              _csp_failures(root) == [], repr(_csp_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # script-src-elem overrides script-src for inline <script> in CSP3, so a
        # permissive script-src-elem must be caught too.
        _write(root, 'index.html', _cpage % (_csp2 % (
            "script-src 'self'; script-src-elem 'self' 'unsafe-inline'"), ''))
        check('script-src-elem unsafe-inline flagged',
              any('unsafe-inline' in f for f in _csp_failures(root)),
              repr(_csp_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # A repeated directive: the browser enforces the FIRST, so a safe first
        # occurrence must pass even though a later one adds 'unsafe-inline'.
        _write(root, 'index.html', _cpage % (_csp2 % (
            "script-src 'self'; script-src 'self' 'unsafe-inline'"), ''))
        check('duplicate script-src keeps the first (safe) value',
              _csp_failures(root) == [], repr(_csp_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # Any external source is flagged by an allowlist (a legit token is a
        # quoted keyword/nonce/hash or a host-free scheme). Bare host, host:port,
        # IPv6, single-label host, and a network scheme all count.
        for bad in ('cdn.example.com', 'cdn.example.com:443', '[::1]',
                    'localhost', 'wss:', '*'):
            _write(root, 'index.html', _cpage % (_csp % ("'self' " + bad), ''))
            check('CSP external source flagged: %s' % bad,
                  any('external source' in f for f in _csp_failures(root)),
                  repr(_csp_failures(root)))
        # A host-free scheme source (data:) is legitimate and must NOT be flagged.
        _write(root, 'index.html', _cpage % (_csp % "'self'", ''))
        check('clean strict CSP has no external-source failure',
              not any('external source' in f for f in _csp_failures(root)),
              repr(_csp_failures(root)))

    # check_no_inline_script: inline <script> body, on*= handler, javascript: URL.
    def _inline_failures(root):
        failures: list[str] = []
        check_site.check_no_inline_script(root, failures)
        return failures

    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<script>doThing();</script>'))
        check('inline <script> body flagged',
              any('inline <script>' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # </script > (whitespace end tag) must still close the block; an external
        # <script src> is the intended shape and must NOT be flagged.
        _write(root, 'a.js', 'doThing();\n')
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<script src="/a.js"></script >'))
        check('external <script src> not flagged',
              _inline_failures(root) == [], repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<button onClick="x()">go</button>'))
        check('inline on*= handler flagged',
              any('onclick' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<a href="javascript:void(0)">x</a>'))
        check('javascript: URL flagged',
              any('javascript:' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # A non-executable data block (JSON-LD, templates) is inert -- the browser
        # never runs it, so it needs no 'unsafe-inline' and must NOT be flagged.
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<script type="application/ld+json">{"@type":"x"}</script>'))
        check('non-executable data <script> not flagged',
              _inline_failures(root) == [], repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # A src attribute of ANY value makes the browser ignore the body.
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<script src="">ignored()</script>'))
        check('<script src=""> body ignored (not flagged)',
              _inline_failures(root) == [], repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # javascript: as a data-* value is just text (these sites SHOW attacks),
        # not a navigable URL -- must NOT be flagged.
        _write(root, 'index.html', _cpage % (_csp % "'self'",
               '<span data-example="javascript:void(0)">x</span>'))
        check('javascript: in a data-* attr not flagged',
              _inline_failures(root) == [], repr(_inline_failures(root)))

    check('check_no_inline_script invoked from main()',
          'check_no_inline_script(root, failures)' in main_body)

    # check_links: a '..'-traversal target that escapes the site root is a BROKEN
    # link (it would 404 on the deployed site), never validated against some
    # unrelated real file that happens to exist on the test host.
    def _links_failures(root, **kw):
        failures: list[str] = []
        check_site.check_links(root, failures, **kw)
        return failures
    cands = check_site._abs_candidates('../../etc/hostname', ['/nonexistent-root'])
    check('_abs_candidates clamps a root-escaping path into the root',
          bool(cands) and all(c.startswith('/nonexistent-root/') for c in cands)
          and cands[0] == '/nonexistent-root/etc/hostname', repr(cands))
    with tempfile.TemporaryDirectory() as root, \
            tempfile.TemporaryDirectory() as outside:
        # A decoy file OUTSIDE the root; a relative '..'-link that lands on it
        # must still be reported broken (throwaway decoy, not a system file).
        with open(os.path.join(outside, 'decoy.html'), 'w',
                  encoding='utf-8') as handle:
            handle.write('x')
        rel = os.path.relpath(os.path.join(outside, 'decoy.html'),
                              os.path.join(root, 'sub'))
        _write(root, 'sub/index.html', '<a href="%s">x</a>' % rel)
        check('root-escaping relative link reported broken',
              any('broken internal link' in f for f in _links_failures(root)),
              repr(_links_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<a href="/sub/">x</a>')
        _write(root, 'sub/index.html', '<p>ok</p>')
        check('same-root link still resolves', _links_failures(root) == [],
              repr(_links_failures(root)))

    # check_supply_chain: srcset candidates and fetching <link> rels are external
    # subresource LOADS too (Extractor records only href/src for the tag loop).
    def _supply_failures(root):
        failures: list[str] = []
        check_site.check_supply_chain(root, failures)
        return failures
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<img srcset="https://example.com/a.webp 2x">')
        check('external srcset flagged by supply-chain',
              any('srcset' in f and 'a.webp' in f
                  for f in _supply_failures(root)), repr(_supply_failures(root)))
        _write(root, 'index.html', _page % '<img srcset="/a.webp 2x">')
        check('same-origin srcset passes supply-chain',
              _supply_failures(root) == [], repr(_supply_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<link rel="stylesheet" href="https://example.com/s.css">')
        check('external stylesheet link flagged',
              any('s.css' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))
        _write(root, 'index.html',
               _page % '<link rel="canonical" href="https://example.com/">')
        check('external canonical link NOT flagged (metadata)',
              _supply_failures(root) == [], repr(_supply_failures(root)))

    # _is_external matches browser URL parsing: case, whitespace, backslash.
    check('_is_external: HTTPS scheme (case-insensitive)',
          check_site._is_external('HTTPS://example.com/x'))
    check('_is_external: leading whitespace trimmed',
          check_site._is_external('  //example.com/x'))
    check('_is_external: backslash treated as slash',
          check_site._is_external('\\\\example.com/x')
          and check_site._is_external('/\\example.com/x'))
    check('_is_external: a same-origin path is not external',
          not check_site._is_external('/local/x'))

    # Browser-style '..' clamping: an in-root '..' link RESOLVES (not broken),
    # and a protocol-relative external link is external (not a broken internal).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<p>home</p>')
        _write(root, 'sub/page.html', '<a href="../index.html">home</a>')
        check('in-root .. link resolves (clamped like a browser)',
              _links_failures(root) == [], repr(_links_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<a href="//other.example.com/p">x</a>')
        check('protocol-relative link is external, not a broken internal link',
              _links_failures(root) == [], repr(_links_failures(root)))

    # supply-chain: external CSS url() (inline, and a .css file) is a load.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page %
               '<div style="background:url(https://example.com/p.webp)">x</div>')
        check('external inline CSS url() flagged by supply-chain',
              any('CSS url()' in f and 'p.webp' in f
                  for f in _supply_failures(root)), repr(_supply_failures(root)))
        _write(root, 'index.html', _page % '<link rel="stylesheet" href="/s.css">')
        _write(root, 's.css', 'body{background:url(https://example.com/bg.webp)}')
        check('external .css url() flagged by supply-chain',
              any('bg.webp' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))

    # supply-chain: an external <object data=...> is a load (previously a dead
    # RESOURCE_ATTR entry, now live via the Extractor).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<object data="https://example.com/x.swf"></object>')
        check('external <object data> flagged by supply-chain',
              any('x.swf' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))

    # srcset via the HTML parser: an unquoted attribute is caught; a srcset
    # substring in a CODE SAMPLE (text, not an attribute) is NOT a false load.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _page % '<img srcset=https://example.com/a.webp>')
        check('unquoted external srcset flagged',
              any('a.webp' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))
        _write(root, 'index.html',
               _page % '<code>srcset="https://example.com/z.webp"</code>')
        check('srcset in a code sample is not a false load',
              _supply_failures(root) == [], repr(_supply_failures(root)))

    # check_footer: a family link appearing AFTER </footer> must not mask a
    # missing one inside the footer.
    def _footer_failures(root):
        failures: list[str] = []
        check_site.check_footer(root, failures)
        return failures
    with tempfile.TemporaryDirectory() as root:
        fam = list(check_site.FAMILY.values())
        _write(root, 'index.html',
               '<footer>%s</footer>\n<!-- %s -->' % (fam[0], ' '.join(fam[1:])))
        check('family links after </footer> do not mask missing ones',
              len(_footer_failures(root)) == len(fam) - 1,
              repr(_footer_failures(root)))

    # check_banner: the status-pill compliance check must not depend on
    # class="status" being the pill's first attribute.
    def _banner_failures_attr_order(root):
        failures: list[str] = []
        check_site.check_banner(root, failures)
        return failures
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<span id="x" class="status">working</span>')
        check('banner pill checked regardless of attribute order',
              any('status banner' in f for f in _banner_failures_attr_order(root)),
              repr(_banner_failures_attr_order(root)))
        _write(root, 'index.html',
               '<span id="x" class="status">review needed</span>')
        check('compliant banner passes regardless of attribute order',
              _banner_failures_attr_order(root) == [], repr(_banner_failures_attr_order(root)))

    # A dotted directory name ('blog.v2/') is a page dir, not a file extension.
    dotted = check_site._abs_candidates('blog.v2/', ['/nonexistent-root'])
    check('_abs_candidates adds index.html for a dotted dir name',
          any(c.endswith('blog.v2/index.html') for c in dotted), repr(dotted))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<a href="/blog.v2/">x</a>')
        _write(root, 'blog.v2/index.html', '<p>ok</p>')
        check('link to a dotted-name directory resolves',
              _links_failures(root) == [], repr(_links_failures(root)))

    # subsite mount matches on a PATH boundary, not a bare string prefix.
    mounted = check_site.resolve_internal(
        '/root', '/root/p.html', '/sub-extra/x',
        mount='/sub', parent_roots=('/parent',))
    check('mount prefix requires a path boundary (sibling not swallowed)',
          mounted == ('file',
                      check_site._abs_candidates('sub-extra/x', ['/parent']), '')
          and all('/root/-extra' not in c for c in mounted[1]), repr(mounted))

    # _is_external sees the control-char and scheme-relative forms a browser
    # accepts (WHATWG strips tab/newline before scheme matching).
    check('_is_external: newline embedded WITHIN the scheme',
          check_site._is_external('ht\ntps://example.com/x'))
    check('_is_external: scheme-relative http: form',
          check_site._is_external('http:example.com/x'))

    # supply-chain: an external CSS @import (bare-string form) is a load.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<style>@import "https://example.com/s.css";</style>')
        check('external CSS @import flagged by supply-chain',
              any('s.css' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))

    # footer: an <article>/<section> footer BEFORE the site footer must not hide
    # the site footer's family links.
    with tempfile.TemporaryDirectory() as root:
        fam = list(check_site.FAMILY.values())
        _write(root, 'index.html',
               '<article><footer>article footer</footer></article>'
               '<footer>%s</footer>' % ' '.join(fam))
        check('article footer before site footer does not mask family links',
              _footer_failures(root) == [], repr(_footer_failures(root)))

    # check_no_inline_script: a javascript: URL with an embedded tab is caught.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<a href="jav\tascript:x()">y</a>')
        check('obfuscated javascript: URL (embedded tab) flagged',
              any('javascript:' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))

    # check_toc_complete: a .cat section missing from the on-this-page TOC is flagged;
    # a complete TOC is clean; a non-section TOC anchor does not force a false positive.
    def _toc_failures(root):
        failures: list[str] = []
        check_site.check_toc_complete(root, failures)
        return failures
    _toc_nav = ('<nav class="toc"><ul>%s</ul></nav>')
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _toc_nav % '<li><a href="#one">One</a></li>'
               + '<section class="cat" id="one">a</section>'
               + '<section class="cat" id="two">b</section>')   # #two absent from TOC
        _tf = _toc_failures(root)
        check('toc-complete flags a section missing from the TOC',
              any('#two' in f for f in _tf), repr(_tf))
        check('toc-complete does not flag the listed section',
              not any('#one' in f for f in _tf), repr(_tf))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _toc_nav % ('<li><a href="#one">One</a></li>'
                           '<li><a href="#row-x">Row</a></li>')   # a non-section anchor
               + '<section class="cat" id="one">a</section>')
        check('toc-complete clean when every .cat section is listed',
              _toc_failures(root) == [], repr(_toc_failures(root)))
    with tempfile.TemporaryDirectory() as root:                  # no TOC -> exempt
        _write(root, 'index.html', '<section class="cat" id="lonely">x</section>')
        check('toc-complete exempts a page with no on-this-page TOC',
              _toc_failures(root) == [], repr(_toc_failures(root)))

    # check_repro_raw: a Reproduce box must show the raw attack in a traditional
    # tool, never pipe the payload into a safety/neutralizer tool (that is the
    # Mitigation box). Canaries reproduce the exact pre-change bug.
    def _repro_failures(root):
        failures: list[str] = []
        check_site.check_repro_raw(root, failures)
        return failures

    _repro = ('<div class="repro"><div class="reprohd">'
              '<a class="repro-try" href="#try">Reproduce</a></div>'
              '<div class="copybox"><code class="cmd">%s</code>'
              '<button class="copybtn" type="button" hidden>Copy</button></div></div>')
    _mitig = ('<div class="mitig"><div class="mitighd">'
              '<a class="mitig-try" href="#how">Mitigation</a></div>'
              '<div class="copybox"><code class="cmd">%s</code>'
              '<button class="copybtn" type="button" hidden>Copy</button></div></div>')

    # A: the pre-change bug -- a Reproduce box piping the payload into stcat.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _repro % 'base64 -d poc/x/payload.b64 | stcat')
        fails = _repro_failures(root)
        check('repro-raw flags stcat in a Reproduce box',
              any('stcat' in f for f in fails), repr(fails))

    # B: the fixed form -- decode to a file, then bare cat -- must pass.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _repro % 'base64 -d poc/x/payload.b64 &gt; payload'
               + _repro % 'cat payload')
        check('repro-raw passes base64-decode + cat',
              _repro_failures(root) == [], repr(_repro_failures(root)))

    # C: the safety tool in a Mitigation box (not .repro) must NOT be flagged.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _repro % 'cat payload' + _mitig % 'stcat payload')
        check('repro-raw ignores a safety tool in a .mitig box',
              _repro_failures(root) == [], repr(_repro_failures(root)))

    # D: unicode-show / text-safety-scan / git-diff-review are caught too, and
    # stcatn (superstring of stcat) does not slip a bare stcat past the match.
    for bad in ('base64 -d poc/x/payload.b64 | unicode-show /dev/stdin',
                'text-safety-scan changelog',
                'git -c diff.external=git-diff-review diff master..x',
                'base64 -d poc/x/payload.b64 | stcatn'):
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html', _repro % bad)
            check('repro-raw flags %r' % bad.split()[-1],
                  _repro_failures(root) != [], bad)

    # E: plain git diff and a normal paste (no neutralizer) pass.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _repro % 'git diff master..type/submodule-bump'
               + _repro % 'wl-copy &lt; paste.payload')
        check('repro-raw passes git diff + wl-copy',
              _repro_failures(root) == [], repr(_repro_failures(root)))

    # F: the check must be WIRED into main() -- a defined-but-uncalled check
    # enforces nothing (the image gate shipped that way once).
    check('check_repro_raw is invoked from main()',
          'check_repro_raw(root, failures)' in main_body)

    # ---- Hardening batch (15 reviewer findings) -----------------------------
    # Each block asserts the fixed behavior and, by construction, FAILS on the
    # pre-fix check_site.py (test-per-bug). F15 is by-design (see the note below).

    # F1: a CSS comment between url()/@import and the value must not hide an
    # external load -- a browser strips /* */ before tokenizing. Pre-fix the
    # comment defeated the scan and the load shipped undetected.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<style>a{background:url(/*x*/"https://example.com/x.png")}</style>')
        check('supply-chain flags url() past a CSS comment',
              any('x.png' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))
        _write(root, 'index.html',
               _page % '<style>@import /*c*/"https://example.com/s.css";</style>')
        check('supply-chain flags @import past a CSS comment',
              any('s.css' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))

    # F2: a leading C0 control byte must not defeat javascript: detection (a
    # browser strips it, so it still executes). F9: NBSP is NOT stripped (a real
    # parser keeps it), so a bare NBSP+http is not a false external. chr() keeps
    # the control byte out of the source literally.
    check('_url_norm strips a leading C0 control (\\x01javascript:)',
          check_site._url_norm(chr(1) + 'javascript:x').startswith('javascript:'))
    check('_url_norm does not strip NBSP (no false external)',
          not check_site._is_external(chr(0xa0) + 'http://example.com/x'))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', '<a href="%sjavascript:x()">y</a>' % chr(1))
        check('C0-obfuscated javascript: URL flagged',
              any('javascript:' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))

    # F3-F6: external subresource loads via attrs the base RESOURCE_ATTR map
    # missed -- legacy background=, <video poster>, SVG <image>/<use>
    # href/xlink:href, and <input type=image src> -- must all be gated.
    for _markup, _needle in (
            ('<body background="https://example.com/bg.png">x</body>', 'bg.png'),
            ('<video poster="https://example.com/p.png" src="/v.webm"></video>', 'p.png'),
            ('<svg><image href="https://example.com/i.png"/></svg>', 'i.png'),
            ('<svg><use xlink:href="https://example.com/s.svg#i"/></svg>', 's.svg'),
            ('<input type="image" src="https://example.com/btn.png">', 'btn.png')):
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html', _page % _markup)
            check('supply-chain gates external load %r' % _needle,
                  any(_needle in f for f in _supply_failures(root)),
                  repr(_supply_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # Canary: a non-image <input src> is not a load, so it is not falsely gated.
        _write(root, 'index.html', _page % '<input type="text" src="https://example.com/x">')
        check('non-image <input src> not gated as a load',
              _supply_failures(root) == [], repr(_supply_failures(root)))

    # F7: an <iframe srcdoc="..."> is a nested document; inline script and
    # external loads inside it must be audited (they were invisible before).
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<iframe srcdoc="&lt;script&gt;evil()&lt;/script&gt;"></iframe>')
        check('inline <script> inside iframe srcdoc flagged',
              any('inline <script>' in f for f in _inline_failures(root)),
              repr(_inline_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               _page % '<iframe srcdoc="&lt;img src=https://example.com/x.png&gt;"></iframe>')
        check('external load inside iframe srcdoc flagged',
              any('x.png' in f for f in _supply_failures(root)),
              repr(_supply_failures(root)))

    # F8: a valid but non-canonically-spaced default-src (two spaces) must pass --
    # the check reads the parsed directive, not an exact substring.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html', _cpage % (_csp % "'self'", ''))
        _base = _csp_failures(root)
        _write(root, 'index.html', _cpage % (
            (_csp % "'self'").replace("default-src 'none'", "default-src  'none'"), ''))
        check("double-spaced default-src 'none' still passes",
              _base == [] and _csp_failures(root) == [], repr(_csp_failures(root)))

    # F10: the status pill must be found regardless of quote style or extra
    # classes (a raw class="status" substring missed both).
    check('single-quoted status pill still checked',
          _banner_failures(_page % "<span class='status'>working</span>") != [])
    check('multi-class status pill still checked',
          _banner_failures(_page % '<span class="status pill">working</span>') != [])
    check('multi-class compliant status pill passes',
          _banner_failures(_page % '<span class="status pill">review needed</span>') == [])

    # F11: a <footer> that exists only inside an HTML comment must read as "no
    # <footer>" (parsed, comments excluded), not emit misdirected missing-family-
    # link errors off the commented markup.
    with tempfile.TemporaryDirectory() as root:
        _write(root, 'index.html',
               '<!-- <footer>%s</footer> -->' % ' '.join(check_site.FAMILY.values()))
        _ff = _footer_failures(root)
        check('comment-only footer reports no <footer>',
              _ff == ['index.html: no <footer>'], repr(_ff))

    # F12: a <nav> carrying an attribute (aria-label) must still yield the header
    # nav, so the page is not silently dropped from the nav-consistency
    # comparison; a single-quoted href is captured too.
    check('header nav with an attribute is still parsed',
          check_site._header_nav(
              '<header><nav aria-label="Main"><a href="/">H</a></nav></header>')
          == (('H', '/'),))
    check('single-quoted nav href is captured',
          check_site._header_nav("<header><nav><a href='/x'>H</a></nav></header>")
          == (('H', '/x'),))

    def _nav_failures(root):
        failures: list[str] = []
        check_site.check_nav(root, failures)
        return failures
    with tempfile.TemporaryDirectory() as root:
        # End-to-end: a page whose header nav differs is now compared (pre-fix its
        # nav attribute made _header_nav return None and the drop hid the diff).
        _nav = '<header><nav%s><a href="/">Home</a>%s</nav></header>'
        _write(root, 'a.html', _nav % ('', '<a href="/faq/">FAQ</a>'))
        _write(root, 'b.html', _nav % ('', '<a href="/faq/">FAQ</a>'))
        _write(root, 'c.html', _nav % (' aria-label="Main"', ''))
        _nf = _nav_failures(root)
        check('nav inconsistency on a page with a nav attribute is caught',
              any('c.html' in f and 'FAQ' in f for f in _nf), repr(_nf))

    # F13: a low-contrast text color expressed as rgb(%), hsl(), or a var() chain
    # must still be caught (pre-fix _parse_color returned None and skipped it).
    for _val, _label in (('rgb(85%,22%,20%)', 'rgb-percent'),
                         ('hsl(3,68%,52%)', 'hsl'),
                         ('var(--brand);--brand:#d83933', 'var-chain')):
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html', _page % '<link rel="stylesheet" href="style.css">')
            _write(root, 'style.css',
                   ':root{--bg:#f3f2ee;--accent:%s}.kicker{color:var(--accent)}' % _val)
            check('low-contrast %s accent flagged' % _label,
                  any('--accent' in f for f in _ct_failures(root)), repr(_ct_failures(root)))
    with tempfile.TemporaryDirectory() as root:
        # Both-way canary: a high-contrast hsl (black) must pass -- proves the math
        # runs on the parsed color, not a constant flag.
        _write(root, 'index.html', _page % '<link rel="stylesheet" href="style.css">')
        _write(root, 'style.css',
               ':root{--bg:#f3f2ee;--accent:hsl(0,0%,0%)}.kicker{color:var(--accent)}')
        check('high-contrast hsl (black) accent passes',
              _ct_failures(root) == [], repr(_ct_failures(root)))

    # F14: a version token (v2023-01) is not a dated claim and must not false-fail;
    # a genuinely aged dated claim still does.
    def _fresh_failures(root):
        failures: list[str] = []
        check_site.check_freshness(root, failures)
        return failures
    _saved_today = os.environ.get('CHECK_SITE_TODAY')
    os.environ['CHECK_SITE_TODAY'] = '2026-09-14'
    try:
        with tempfile.TemporaryDirectory() as root:
            _write(root, 'index.html', _page % '<p>updated in v2023-01 release notes</p>')
            check('version string v2023-01 is not flagged as a dated claim',
                  _fresh_failures(root) == [], repr(_fresh_failures(root)))
            _write(root, 'index.html', _page % '<p>as of 2020-01-01 the data held</p>')
            check('a genuinely aged dated claim is still flagged',
                  any('dated claim' in f for f in _fresh_failures(root)),
                  repr(_fresh_failures(root)))
    finally:
        if _saved_today is None:
            os.environ.pop('CHECK_SITE_TODAY', None)
        else:
            os.environ['CHECK_SITE_TODAY'] = _saved_today

    # F15 (by-design, NOT changed): html_files() skips a .html with a same-basename
    # image sibling because that is the render-source convention (logo-wide.html ->
    # logo-wide.webp), asserted by case 12 above. The theoretical over-broadening (a
    # content page coincidentally named like a screenshot) has no reliable structural
    # signal to tighten on without breaking case 12, and the sites' naming avoids it.

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
