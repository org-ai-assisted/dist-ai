#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shell-invocation guard: under bash/sh the shebang is ignored and the `import`
## lines below would run as shell commands (`import` is ImageMagick -> XGrabServer,
## which freezes X). Re-exec under python3; inert as a string literal in python3.
## (This is an IMPORTED module, never run directly -- the guard is belt-and-suspenders.)
"exec" "python3" "-Bsu" "$0" "$@"

## Shared parsing for the secure-terminal.github.io shot-gallery guards
## (secure-terminal-shots-inventory: orphan/dangling; secure-terminal-shots-dims:
## declared <img> dimensions vs the referenced asset's intrinsic pixels).
##
## The reference-resolution logic (query/fragment stripping, percent-decoding, normpath,
## gallery-prefix match) is subtle and MUST stay identical across both guards -- a hand copy
## drifts silently and re-opens the exact evasion holes the comments below document. So it
## lives here once and both tools import it.

import os
from html.parser import HTMLParser
from urllib.parse import unquote

## The galleries these guards own. A file directly under one of these (recursively) is a
## "shot"; a reference whose resolved path lands under one of these targets a shot.
GALLERY_DIRS = ('shots', 'comparison/shots', 'compatibility/shots')
IMAGE_EXTS = ('.webp', '.png', '.jpg', '.jpeg', '.gif', '.svg')


class SiteError(Exception):
    """A bad site checkout (missing, or no galleries) -- maps to a tool exit code of 2."""


class RefCollector(HTMLParser):
    """Collect src/href/srcset attribute values (the page's local resource references)."""

    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if not value:
                continue
            if name in ('src', 'href'):
                self.refs.append(value)
            elif name == 'srcset':
                ## srcset is a comma-separated list of "<url> [descriptor]" candidates
                ## (e.g. 'a.webp 1x, b.webp 2x'); collect each URL, or a shot referenced
                ## only via srcset (a missing one) is invisible to the dangling-ref guard.
                for candidate in value.split(','):
                    fields = candidate.split()
                    if fields:
                        self.refs.append(fields[0])


class ImgDimCollector(HTMLParser):
    """Collect every <img> as (src, width, height); width/height are the RAW attribute
    strings (or None when absent), so the caller decides what counts as a pixel pin."""

    def __init__(self):
        super().__init__()
        self.images = []

    def handle_starttag(self, tag, attrs):
        if tag != 'img':
            return
        ## FIRST occurrence of each attribute, not dict(attrs) (which keeps the LAST): on a
        ## duplicate width/height the browser lays out with the FIRST per HTML5, so the guard
        ## must judge the pin the browser actually uses.
        src = width = height = None
        for name, value in attrs:
            if name == 'src' and src is None:
                src = value
            elif name == 'width' and width is None:
                width = value
            elif name == 'height' and height is None:
                height = value
        if not src:
            ## srcset-only <img> carries no single intrinsic target to pin against; the
            ## inventory guard covers its existence, this guard skips it.
            return
        self.images.append((src, width, height))

    def handle_startendtag(self, tag, attrs):
        ## self-closing '<img .../>' -- HTMLParser routes it here, not to handle_starttag.
        self.handle_starttag(tag, attrs)


def resolve_ref(ref, html_path, site):
    """Resolve a page reference to a site-relative POSIX path, or None if it is external
    or not a local image. Handles a root-absolute ('/a/b.webp') and a relative ('shots/x')
    reference (relative to the HTML file's own directory), matching how a browser + GitHub
    Pages serve them."""
    if ('://' in ref) or ref.startswith('//') or ref.startswith('data:') \
            or ref.startswith('mailto:') or ref.startswith('#'):
        return None
    ## Strip ?query / #fragment BEFORE the extension check: a real image reference can
    ## carry a cache-buster ('shots/x.webp?v=2') or fragment, which otherwise fails the
    ## endswith() test -> the reference is dropped, producing a false "orphan shot" (and
    ## equally hiding a genuine dangling reference that carries a query/fragment).
    path = ref.split('?', 1)[0].split('#', 1)[0]
    ## URL-decode before the extension check + file match: a browser requests the DECODED
    ## path, so a percent-encoded reference ('shots/x%2Ewebp', 'shots/a%20b.webp') otherwise
    ## fails endswith()/os.path lookup -> a dangling %-encoded ref evades the guard (and a real
    ## one is mismatched to its file). The '?'/'#' split above uses the RAW delimiters first, so
    ## an encoded %3F/%23 inside the path is preserved for the browser-equivalent decode here.
    path = unquote(path)
    if not path.lower().endswith(IMAGE_EXTS):
        return None
    ## normpath BOTH branches: in_gallery matches by exact prefix, so an un-normalized
    ## '//' or '/./' in a root-absolute ref (e.g. '/comparison//shots/x.webp') would not
    ## start with 'comparison/shots/' and be silently excluded from the gallery -> a real
    ## dangling reference goes unreported (the relative branch already normalized; the
    ## root-absolute one only lstrip'd).
    if path.startswith('/'):
        rel = os.path.normpath(path.lstrip('/'))
    else:
        base = os.path.relpath(os.path.dirname(html_path), site)
        rel = os.path.normpath(os.path.join(base, path))
    return rel.replace(os.sep, '/')


def in_gallery(rel):
    return any(rel == d or rel.startswith(d + '/') for d in GALLERY_DIRS)


def default_site():
    return (os.environ.get('SECURE_TERMINAL_SITE_REPO')
            or os.path.expanduser('~/private-sources/secure-terminal.github.io'))


def resolve_site(explicit=None):
    """Return (abspath site, [present gallery dirs]) or raise SiteError. Precedence:
    explicit arg > SECURE_TERMINAL_SITE_REPO env > default checkout path."""
    site = os.path.abspath(explicit if explicit else default_site())
    if not os.path.isdir(site):
        raise SiteError('site checkout not found: %s' % site)
    present = [d for d in GALLERY_DIRS if os.path.isdir(os.path.join(site, d))]
    if not present:
        raise SiteError('no shot galleries under %s (expected one of: %s)'
                        % (site, ', '.join(GALLERY_DIRS)))
    return site, present


def iter_html_paths(site):
    """Yield every '*.html' file under site (skipping .git), in os.walk order."""
    for root, dirs, names in os.walk(site):
        if '.git' in dirs:
            dirs.remove('.git')
        for n in names:
            if n.endswith('.html'):
                yield os.path.join(root, n)


def collect_from_pages(site, collector_factory):
    """Feed every page through a fresh collector_factory() instance; return a list of
    (html_path, collector). Raise SiteError on any unreadable page (a broken checkout must
    fail loud, never silently skip a page and under-report drift)."""
    pages = []
    for html_path in iter_html_paths(site):
        collector = collector_factory()
        try:
            with open(html_path, encoding='utf-8') as handle:
                collector.feed(handle.read())
        except (OSError, UnicodeDecodeError) as exc:
            raise SiteError('cannot read %s: %s' % (html_path, exc))
        pages.append((html_path, collector))
    return pages


def collect_shot_files(site, present_galleries):
    """Every committed shot file (site-relative POSIX path) under the present galleries."""
    shot_files = set()
    for d in present_galleries:
        for root, _dirs, names in os.walk(os.path.join(site, d)):
            for n in names:
                if n.lower().endswith(IMAGE_EXTS):
                    rel = os.path.relpath(os.path.join(root, n), site)
                    shot_files.add(rel.replace(os.sep, '/'))
    return shot_files
