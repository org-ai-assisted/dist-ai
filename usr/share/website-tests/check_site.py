#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static checks for the project's GitHub Pages sites (output-lies.github.io,
secure-terminal.github.io, org-ai-assisted.github.io). Catches the bug classes
that shipped before: broken internal links, missing footer "family" links,
lowercase "open source"/"free software" in prose, a wrong review-status
banner, and images orphaned when their section is deleted. Pure standard
library, no network.

Usage: check_site.py <site-root> [<site-root> ...]
Exit 0 if all checks pass, 1 on any failure, 77 (SKIP) if no root resolves.

Each <site-root> is the directory holding a site's index.html. The site's own
identity is inferred from its directory name (matched against the known family).
"""

import calendar
import datetime
import html.parser
import math
import os
import posixpath
import re
import sys
import urllib.parse

# The family of sibling Pages sites: every site's footer must link to all of
# them (the current one included -- rendered as a self-link).
FAMILY = {
    'output-lies.github.io':    'https://output-lies.github.io',
    'secure-terminal.github.io': 'https://secure-terminal.github.io',
    'org-ai-assisted.github.io': 'https://org-ai-assisted.github.io',
}

# Same-domain paths served by a SIBLING project-Pages repo (e.g.
# output-lies.github.io/git-diffs-lie/ is built from output-lies/git-diffs-lie),
# so they are valid live URLs even though no file for them exists in THIS repo.
# Verified deployed via the Pages API; treated as external (not a local file).
KNOWN_PROJECT_PATHS: tuple[str, ...] = (
)

# Sub-sites served UNDER another family site's domain (a project-Pages repo): the
# subsite's directory basename -> (parent site directory basename, mount path
# under the parent domain). A subsite's root-absolute links resolve against its
# OWN tree when they fall under the mount, and against the PARENT site's tree
# otherwise (a link like /terminal/ from git-diffs-lie points at the output-lies
# site). Both must be checked out to verify the cross-site links; when the parent
# is absent those links are treated as external (unverifiable), never failed.
SUBSITES: dict[str, tuple[str, str]] = {
}

# Prose wording rule: these must be capitalized as proper labels.
WORDING = [
    (re.compile(r'\bopen source\b'), 'open source', 'Open Source'),
    (re.compile(r'\bfree software\b'), 'free software', 'Free Software'),
]


class _HTMLScopeParser(html.parser.HTMLParser):
    """HTMLParser that models HTML5 self-closing correctly for scope tracking: a
    browser IGNORES a trailing '/' on a NON-void element, leaving it OPEN, so
    `<div/>` / `<section/>` / `<footer/>` must read as a plain start tag -- not the
    stdlib default's immediate open-then-close, which mis-scopes (or drops) every
    node that a real browser renders inside the still-open element. Void elements
    keep open-then-close. Scope-tracking audits subclass this instead of
    html.parser.HTMLParser so a stray self-closing slash cannot defeat them."""

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in VOID_TAGS:
            self.handle_endtag(tag)


class Extractor(html.parser.HTMLParser):
    """Collect (attr) link targets, element ids, and the concatenated visible
    text (script/style excluded) of one HTML document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # (tag, attr, value) for href/src/data
        self.loads = []          # (tag, attr, value) subresource LOADS (supply-chain)
        self.srcdocs = []        # iframe srcdoc HTML: a nested document to recurse
        self.link_rels = []      # (rel-tokens, href) for every <link href=...>
        self.srcsets = []        # srcset attribute values (char-refs decoded)
        self.ids = set()
        self.text_parts = []
        self.csp = None          # content of the CSP <meta http-equiv>
        self.styles = []         # CSS text: style="" attrs + <style> element bodies
        self._skip = 0
        self._in_style = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
        if tag == 'style':
            self._in_style += 1
        amap = dict(attrs)
        if amap.get('id'):
            self.ids.add(amap['id'])
        if amap.get('name') and tag == 'a':
            self.ids.add(amap['name'])
        if amap.get('style'):
            self.styles.append(amap['style'])
        if tag == 'meta' and (amap.get('http-equiv') or '').lower() \
                == 'content-security-policy':
            self.csp = amap.get('content') or ''
        if tag == 'link' and amap.get('href'):
            self.link_rels.append(
                ((amap.get('rel') or '').lower().split(), amap['href']))
        if amap.get('srcset'):
            self.srcsets.append(amap['srcset'])
        # <object data=...> is a subresource load (RESOURCE_ATTR); capture it so
        # that entry is not dead. Scoped to <object> so a stray data="" attribute
        # on another element is never mistaken for a link.
        if tag == 'object' and amap.get('data'):
            self.links.append((tag, 'data', amap['data']))
        for key in ('href', 'src'):
            if key in amap and amap[key] is not None:
                self.links.append((tag, key, amap[key]))
        # Subresource loads (supply-chain surface): the RESOURCE_ATTR base plus the
        # attrs it misses (poster, legacy background=, SVG href/xlink:href, input
        # type=image). Kept separate from `links` so link/format checks are unchanged.
        for load_attr, load_val in _resource_loads(tag, amap):
            self.loads.append((tag, load_attr, load_val))
        if tag == 'iframe' and amap.get('srcdoc'):
            self.srcdocs.append(amap['srcdoc'])

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1
        if tag == 'style' and self._in_style:
            self._in_style -= 1

    def handle_data(self, data):
        if self._in_style:
            self.styles.append(data)
        if not self._skip:
            self.text_parts.append(data)

    def text(self):
        return ''.join(self.text_parts)


def _prune_git(dirs):
    # Skip the git metadata dir by EXACT name, in place, so os.walk does not
    # descend into it. A substring test on the path (`'/.git' in base`) is wrong
    # both ways: it also matches '.github' (dropping a real reference source) and,
    # if the checkout path itself contains '.git', matches every directory.
    if '.git' in dirs:
        dirs.remove('.git')


def html_files(root):
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        present = set(files)
        for name in files:
            if not name.endswith('.html'):
                continue
            # Skip image-generation templates (logo.html -> logo.png/.webp,
            # og.html -> og.png, ...): a .html with a same-basename image sibling
            # is a render source for an image, not a navigable page. .webp is
            # included because a content render source is converted to webp.
            stem = name[:-5]
            if any(stem + ext in present
                   for ext in ('.png', '.webp', '.jpg', '.jpeg', '.gif')):
                continue
            yield os.path.join(base, name)


def _clamp(rel):
    """Collapse a root-relative path the way a browser / static server does:
    leading '..' segments above the root are dropped (so the path can never
    escape the checkout to an unrelated real file), while a '..' that stays
    inside still resolves."""
    return posixpath.normpath('/' + rel).lstrip('/')


def _abs_candidates(rel, search_roots):
    """Filesystem candidates for a root-absolute path `rel` across search_roots,
    with '..' clamped at each root so a candidate can never escape it (matching
    how a static server serves the path)."""
    # Capture the directory intent BEFORE clamp (posixpath.normpath strips the
    # trailing '/'); also treat a real directory as one even if its name has a
    # dot (a 'blog.v2/' would otherwise look like it has a file extension).
    is_dir = rel == '' or rel.endswith('/')
    rel = _clamp(rel)
    candidates = []
    for sr in search_roots:
        base = os.path.normpath(os.path.join(sr, rel))
        candidates.append(base)
        if is_dir or not os.path.splitext(base)[1] or os.path.isdir(base):
            candidates += [os.path.join(base, 'index.html'), base + '.html']
    return candidates


def resolve_internal(root, page, target, mount=None, parent_roots=()):
    """Map an internal href/src to a filesystem path candidate list, or None if
    the link is external / a pure fragment / non-navigational. For a subsite,
    `mount` is its path under the parent domain and `parent_roots` are the parent
    site checkouts its off-mount absolute links resolve against."""
    if _is_external(target) or _url_norm(target).startswith(
            ('mailto:', 'tel:', 'data:', 'javascript:')):
        return None
    frag = ''
    if '#' in target:
        target, frag = target.split('#', 1)
    # A query string (a cache-buster like style.css?v=2) is a valid same-origin
    # URL; the static server ignores it and returns the file, so resolve against
    # the path only. Fragment is split first so path?query#frag keeps its frag.
    if '?' in target:
        target = target.split('?', 1)[0]
    if target == '':
        return ('#self', None, frag)         # same-page fragment (no candidate list)
    if target.startswith('/'):
        # A subsite's own mount prefix (/git-diffs-lie/...) maps back onto its own
        # tree, so verify it there rather than skipping it as an external sibling.
        mnt = mount.rstrip('/') if mount else mount
        if mount and (target == mnt or target.startswith(mnt + '/')):
            # Match on a PATH boundary, not a bare string prefix, so a sibling
            # like /git-diffs-lie-extra/ is not mistaken for /git-diffs-lie/.
            return ('file',
                    _abs_candidates(target[len(mnt):].lstrip('/'), [root]), frag)
        if mount:
            # A subsite's OFF-mount absolute link (/terminal/, /paste/, ...) points
            # at the PARENT site, so verify it ONLY there -- searching the subsite
            # too could let a coincidental child path mask a broken parent link.
            # With no parent checked out it is external / unverifiable, not a fail.
            if not parent_roots:
                return None
            return ('file', _abs_candidates(target.lstrip('/'), list(parent_roots)), frag)
        if any(target.startswith(prefix) for prefix in KNOWN_PROJECT_PATHS):
            return None                          # valid sibling project-Pages path
        return ('file', _abs_candidates(target.lstrip('/'), [root]), frag)
    # Resolve the relative link as a URL path against the page's own URL,
    # clamping '..' at the site root exactly as a browser does (urljoin drops the
    # leading '..' rather than escaping), then map that in-root path to disk.
    page_url = '/' + os.path.relpath(page, root).replace(os.sep, '/')
    resolved = urllib.parse.urljoin(page_url, target)
    base = os.path.normpath(os.path.join(root, _clamp(resolved.lstrip('/'))))
    candidates = [base]
    if target.endswith('/') or resolved.endswith('/') \
            or not os.path.splitext(base)[1] or os.path.isdir(base):
        candidates += [os.path.join(base, 'index.html'), base + '.html']
    return ('file', candidates, frag)


_IDS_CACHE: dict[str, set[str] | None] = {}


def _ids_of(path):
    """The element ids of an HTML file (cached), or None if it cannot be read.
    Used to validate a fragment against a page outside the current root (a
    subsite's cross-site link into its parent site)."""
    key = os.path.normpath(path)
    if key not in _IDS_CACHE:
        try:
            ext = Extractor()
            with open(key, encoding='utf-8') as handle:
                ext.feed(handle.read())
            _IDS_CACHE[key] = ext.ids
        except OSError:
            _IDS_CACHE[key] = None
    return _IDS_CACHE[key]


def check_links(root, failures, mount=None, parent_roots=()):
    # Preload ids per page for fragment checks.
    pages = {}
    for page in html_files(root):
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        pages[os.path.normpath(page)] = ext
    for page, ext in pages.items():
        rel = os.path.relpath(page, root)
        for _tag, _attr, value in ext.links:
            resolved = resolve_internal(root, page, value, mount, parent_roots)
            if resolved is None:
                continue
            if resolved[0] == '#self':
                frag = resolved[2]
                if frag and frag not in ext.ids:
                    failures.append(
                        '%s: broken in-page anchor #%s' % (rel, frag))
                continue
            _tag, candidates, frag = resolved
            hit = next((c for c in candidates if os.path.isfile(c)), None)
            if hit is None:
                target = candidates[0] if candidates else value
                failures.append('%s: broken internal link %r -> %s'
                                % (rel, value, target))
                continue
            if frag:
                # The target may live in a PARENT site (a subsite's cross-site
                # link), which is not in this root's `pages`; load its ids on
                # demand so a missing cross-site anchor is caught, not silently
                # accepted.
                target_ids = pages[hit].ids if hit in pages else _ids_of(hit)
                if target_ids is not None and frag not in target_ids:
                    failures.append('%s: link %r targets missing #%s'
                                    % (rel, value, frag))


def check_wording(root, failures):
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        text = ext.text()
        for pattern, bad, good in WORDING:
            if pattern.search(text):
                failures.append('%s: prose uses %r; use %r'
                                % (rel, bad, good))


# A verifiable claim stamped with a date (a coverage %, a line count, a "tested
# on") goes stale silently as the code moves on. Flag any dated claim that has
# aged past the threshold so it gets re-verified and re-dated -- the date is the
# contract that it was true THEN, and this is the backstop that it is checked
# AGAIN. A reproducible run or a test can pin "today" via CHECK_SITE_TODAY.
_DATED_CLAIM = re.compile(
    r'(?:measured|tested|re-verified|verified|re-counted|counted|as of|updated'
    r'|last (?:checked|updated|tested))\b[^.]{0,32}?'
    # The year must not sit directly after an alnum: a version token ("v2023-01",
    # "build2024-05") is not a dated claim, and flagging it false-fails CI on
    # ordinary prose. A real claim has a separator (space/"in "/...) before the year.
    r'(?<![A-Za-z0-9])(\d{4})-(\d{2})(?:-(\d{2}))?', re.IGNORECASE)
_STALE_DAYS = 400


def _today():
    override = os.environ.get('CHECK_SITE_TODAY')
    return datetime.date.fromisoformat(override) if override else datetime.date.today()


def check_freshness(root, failures):
    today = _today()
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        # collapse HTML whitespace the way a browser renders it, so a claim wrapped
        # across source lines ("tested\n2025-01-01") is still matched
        text = re.sub(r'\s+', ' ', ext.text())
        for match in _DATED_CLAIM.finditer(text):
            year, month = int(match.group(1)), int(match.group(2))
            # a month-only claim (YYYY-MM) is measured from the month's LAST day, so
            # it is not aged early -- it stays fresh until the whole month is past.
            # monthrange() is inside the try: a malformed month (e.g. 2025-13) raises
            # calendar.IllegalMonthError (a ValueError), which must be skipped, not crash.
            try:
                day = int(match.group(3)) if match.group(3) \
                    else calendar.monthrange(year, month)[1]
                claim_date = datetime.date(year, month, day)
            except ValueError:
                continue
            age = (today - claim_date).days
            if age > _STALE_DAYS:
                failures.append(
                    '%s: dated claim %r is %d days old (> %d); re-verify and update the date'
                    % (rel, match.group(0).strip(), age, _STALE_DAYS))


class _FooterAudit(_HTMLScopeParser):
    """The concatenated href/text content of every <footer>...</footer> region,
    plus whether any real <footer> exists. Parsed, not raw-markup regex, so a
    <footer> inside an HTML comment is ignored (HTMLParser never fires inside a
    comment) -- a comment-only footer must read as 'no <footer>', not as a footer
    that is missing its family links. Nested footers union, matching the site
    footer + article/section footers the old regex also unioned."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._depth = 0
        self.saw = False
        self._buf = []

    def handle_starttag(self, tag, attrs):
        if tag == 'footer':
            self._depth += 1
            self.saw = True
        if self._depth:
            for _key, value in attrs:
                if value:
                    self._buf.append(value)

    def handle_data(self, data):
        if self._depth:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == 'footer' and self._depth:
            self._depth -= 1

    def scope(self):
        return ' '.join(self._buf).lower()


def check_footer(root, failures):
    index = os.path.join(root, 'index.html')
    if not os.path.isfile(index):
        return
    with open(index, encoding='utf-8') as handle:
        markup = handle.read()
    audit = _FooterAudit()
    audit.feed(markup)
    if not audit.saw:
        failures.append('index.html: no <footer>')
        return
    # Check the family links against the union of ALL <footer> regions: content
    # AFTER a footer must not mask a missing link (the whole-tail bug), and an
    # earlier <article>/<section> footer must not hide the site footer.
    scope = audit.scope()
    for name, url in FAMILY.items():
        if url not in scope:
            failures.append('index.html: footer missing family link %s' % url)


class _StatusPillAudit(_HTMLScopeParser):
    """Text of the first review-status pill: a <span>/<a> whose class token set
    contains 'status'. Parsed, not substring-matched, so a single-quoted or
    multi-class attribute (class='status', class="status pill") -- which the old
    raw-markup match silently skipped -- is still checked."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._pill_tag = None
        self._depth = 0
        self._buf = []
        self.text = None

    def handle_starttag(self, tag, attrs):
        if self._pill_tag is None and self.text is None:
            if tag in ('span', 'a') and \
                    'status' in (dict(attrs).get('class') or '').split():
                self._pill_tag = tag
                self._depth = 1
                self._buf = []
        elif self._pill_tag == tag:
            self._depth += 1        # a nested same-name tag inside the pill

    def handle_data(self, data):
        if self._pill_tag is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if self._pill_tag is not None and tag == self._pill_tag:
            self._depth -= 1
            if self._depth == 0:
                self.text = ''.join(self._buf)
                self._pill_tag = None


def check_banner(root, failures):
    index = os.path.join(root, 'index.html')
    if not os.path.isfile(index):
        return
    with open(index, encoding='utf-8') as handle:
        markup = handle.read()
    # A review-status pill, WHERE PRESENT, must say review is needed -- never a
    # "working"/green claim. Not every site carries one, so absence is allowed.
    audit = _StatusPillAudit()
    audit.feed(markup)
    if audit.text is not None and 'review' not in audit.text.lower():
        failures.append('index.html: status banner is %r; must indicate '
                        'human review needed' % audit.text.strip())


# Elements whose named attribute FETCHES a subresource at load time (unlike an
# <a href> or a <link rel=canonical>, which are navigation/metadata, not loads).
RESOURCE_ATTR = {
    'script': 'src', 'img': 'src', 'iframe': 'src', 'source': 'src',
    'embed': 'src', 'audio': 'src', 'video': 'src', 'track': 'src',
    'object': 'data',
}


def _resource_loads(tag, amap):
    """(attr, value) pairs on this element that FETCH a subresource at load time --
    the supply-chain surface. Beyond RESOURCE_ATTR's one-attr-per-tag base: a
    <video poster>, the legacy background= image, an SVG <image>/<use> href or
    xlink:href, and an <input type=image src> are all loads the base map misses."""
    loads = []
    base = RESOURCE_ATTR.get(tag)
    if base and amap.get(base):
        loads.append((base, amap[base]))
    if tag == 'video' and amap.get('poster'):
        loads.append(('poster', amap['poster']))
    if amap.get('background'):
        loads.append(('background', amap['background']))
    if tag in ('image', 'use'):
        for attr in ('href', 'xlink:href'):
            if amap.get(attr):
                loads.append((attr, amap[attr]))
    if tag == 'input' and (amap.get('type') or '').lower() == 'image' \
            and amap.get('src'):
        loads.append(('src', amap['src']))
    return loads


# <link rel> values whose href the browser FETCHES as a subresource, so an
# external one is a supply-chain load. Pure metadata / connection hints
# (canonical, alternate, dns-prefetch, preconnect, prev/next/author/license/
# search, ...) fetch nothing and are NOT gated.
FETCHING_LINK_RELS = frozenset({
    'stylesheet', 'preload', 'modulepreload', 'prefetch',
    'icon', 'apple-touch-icon', 'mask-icon', 'manifest',
})

# Content raster references (an <img>/<source> load, a CSS url(), or an <a href>
# to an image) must be webp -- the site-image-optimize tool converts them, so a
# leftover .png/.jpg is either unoptimized or a rewrite that missed. og:image /
# twitter:image (<meta content=...>) and favicons (<link rel=icon>) are NOT loads
# in this sense (Extractor sees no href/src for meta, and links are excluded
# below), so they legitimately stay PNG/JPEG for social-scraper compatibility.
_RASTER_REF = re.compile(r'\.(?:png|jpe?g)$', re.IGNORECASE)
# url() with a quoted value may legitimately contain ')'; match the quoted forms
# whole, and only forbid ')' in the UNQUOTED form (where it ends the url()).
_CSS_URL = re.compile(
    r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^'"()\s]+))\s*\)""", re.IGNORECASE)
# A browser strips /* */ comments before tokenizing CSS, but a /* inside a string
# is NOT a comment. Skip over "..." / '...' strings first (keep them verbatim) and
# drop only real comments -- otherwise a `content:"/*"` ... `content:"*/"` pair
# would swallow a real url()/@import between them (a false negative). A comment is
# a token SEPARATOR (CSS Syntax 3), so replace it with a space: `@import/* */"..."`
# stays `@import "..."` (a real load), while `url/* */(` correctly does NOT become
# a url-token (a browser does not fetch it either).
_CSS_COMMENT_OR_STRING = re.compile(
    r'''"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(/\*.*?\*/)''', re.DOTALL)


def _strip_css_comments(text):
    return _CSS_COMMENT_OR_STRING.sub(
        lambda m: ' ' if m.group(1) is not None else m.group(0), text)


def _css_urls(text):
    for match in _CSS_URL.finditer(_strip_css_comments(text)):
        yield next(group for group in match.groups() if group is not None)


# @import loads a stylesheet; its bare-string form (@import "url";) is not a
# url() so _CSS_URL misses it -- match it here for the supply-chain scan.
_CSS_IMPORT = re.compile(
    r"""@import\s+(?:url\(\s*)?["']?([^"')\s;]+)""", re.IGNORECASE)


def _css_external_refs(text):
    text = _strip_css_comments(text)
    yield from _css_urls(text)
    for match in _CSS_IMPORT.finditer(text):
        yield match.group(1)
# Basenames a human has cleared to remain a raster (webp came out no smaller).
# Keep this SMALL and justified; every entry is a content image that stays PNG.
STATIC_IMAGE_ALLOWLIST: frozenset[str] = frozenset()


_URL_STRIP = str.maketrans('', '', '\t\n\r')
# Leading/trailing bytes a browser removes before scheme matching: any C0 control
# (0x00-0x1f) or space (0x20). Bare str.strip() is wrong both ways -- it leaves a
# leading \x01 (which the browser DROPS, so \x01javascript: still executes) and it
# strips NBSP (which the browser KEEPS, so a real parser never treats it as blank).
_URL_TRIM = ''.join(chr(code) for code in range(0x21))


def _url_norm(url):
    # Normalize a URL reference the way a browser does before scheme matching:
    # ASCII tab/newline/CR are removed from ANYWHERE (WHATWG), leading/trailing C0
    # controls and space are trimmed, '\' is a '/' for a special scheme, and the
    # scheme compares case-insensitively -- so none of those forms can smuggle a
    # cross-origin load or a javascript: URL past the gate.
    return url.translate(_URL_STRIP).strip(_URL_TRIM).replace('\\', '/').lower()


def _is_external(url):
    # 'http:'/'https:' also covers the scheme-relative 'http:host' form (no //).
    return _url_norm(url).startswith(('http:', 'https:', '//'))


def _is_raster(url):
    return bool(_RASTER_REF.search(url.split('#', 1)[0].split('?', 1)[0]))


def _allowed_raster(url):
    base = os.path.basename(url.split('#', 1)[0].split('?', 1)[0])
    return base in STATIC_IMAGE_ALLOWLIST


def check_image_format(root, failures):
    # Content raster references must be webp (except the static allowlist). Covers
    # <img>/<source> src, srcset candidates, <a href> to a raster, and CSS url()
    # in a .css file or an inline/embedded style.
    def scan(ext, rel):
        for tag, attr, value in ext.links:
            # Only the site's OWN rasters can be converted; an external URL is a
            # supply-chain concern (gated there), not a must-be-webp target.
            if _is_external(value):
                continue
            content = (tag in ('img', 'source') and attr == 'src') or \
                (tag == 'a' and attr == 'href' and _is_raster(value))
            if content and _is_raster(value) and not _allowed_raster(value):
                failures.append('%s: content image %r must be webp (convert with '
                                'site-image-optimize)' % (rel, value))
        for srcset in ext.srcsets:
            for candidate in srcset.split(','):
                token = candidate.strip().split()
                if token and _is_raster(token[0]) and not _is_external(token[0]) \
                        and not _allowed_raster(token[0]):
                    failures.append('%s: srcset image %r must be webp'
                                    % (rel, token[0]))
        for value in _css_external_refs('\n'.join(ext.styles)):
            if _is_raster(value) and not _allowed_raster(value):
                failures.append('%s: CSS url() image %r must be webp'
                                % (rel, value))
        # A raster inside an <iframe srcdoc> is a content image too; recurse
        # (nested srcdoc included), consistent with supply-chain/inline-script.
        for srcdoc in ext.srcdocs:
            sub = Extractor()
            sub.feed(srcdoc)
            scan(sub, rel)

    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        scan(ext, rel)
    for base_dir, dirs, files in os.walk(root):
        if '.git' in dirs:
            dirs.remove('.git')
        for name in files:
            if not name.endswith('.css'):
                continue
            path = os.path.join(base_dir, name)
            rel = os.path.relpath(path, root)
            with open(path, encoding='utf-8') as handle:
                css = handle.read()
            for value in _css_urls(css):
                if _is_raster(value) and not _allowed_raster(value):
                    failures.append('%s: CSS url() image %r must be webp'
                                    % (rel, value))


# Host-free CSP scheme-sources: they name no external host, so they are allowed --
# EXCEPT in a script directive, where a code-bearing scheme (data:/blob:) permits
# arbitrary <script src="data:..."> execution, equivalent to 'unsafe-inline'.
_CSP_SAFE_SCHEMES = frozenset({'data:', 'blob:', 'mediastream:', 'filesystem:'})
# Directives that govern script execution: a host-free scheme is NOT safe here.
_CSP_SCRIPT_DIRECTIVES = frozenset({
    'script-src', 'script-src-elem', 'script-src-attr',
})
# CSP directives whose value is NOT a source list -- a bare word there is a
# report target / flag / type name, never a host, so it is not host-checked.
_CSP_NON_SOURCE = frozenset({
    'report-uri', 'report-to', 'sandbox', 'trusted-types',
    'require-trusted-types-for', 'upgrade-insecure-requests',
    'block-all-mixed-content',
})


def _csp_directives(csp):
    # CSP is ';'-separated directives; each is a whitespace-separated name then
    # its source tokens. Return {name: [tokens]} (all lower-cased). A repeated
    # directive is ignored by the browser after its FIRST occurrence, so keep
    # the first (setdefault) -- matching what the page actually enforces.
    out: dict[str, list[str]] = {}
    for part in csp.split(';'):
        toks = part.split()
        if toks:
            out.setdefault(toks[0].lower(), [t.lower() for t in toks[1:]])
    return out


def check_csp(root, failures):
    # Every page must carry a strict CSP: default-src 'none', no external host
    # allow-listed, and scripts confined to same-origin files -- script-src must
    # NOT permit 'unsafe-inline'. That is what lets every inline <script> move to
    # an external .js and keeps the policy nonce-free and hash-free.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        if ext.csp is None:
            failures.append('%s: no Content-Security-Policy meta' % rel)
            continue
        csp = ext.csp.lower()
        directives = _csp_directives(csp)
        # Whitespace-robust: parse the directive, don't substring-match the exact
        # "default-src 'none'" spelling (two spaces is a valid, equivalent CSP a
        # bare-substring test false-fails). Still fails a missing/loosened value.
        if directives.get('default-src') != ["'none'"]:
            failures.append("%s: CSP default-src is not 'none'" % rel)
        # base-uri does NOT fall back to default-src, so without it a <base href>
        # can rehome every relative script/style/image URL to an external origin,
        # invisible to the other checks. Require it restricted to 'none'/'self'.
        if directives.get('base-uri') not in (["'none'"], ["'self'"]):
            failures.append("%s: CSP base-uri is not 'none'/'self' (a <base> can "
                            "rehome every relative URL)" % rel)
        # No external source may be allow-listed. A legitimate source token is a
        # quoted keyword / nonce / hash ("'self'", "'sha256-...'") or a host-free
        # scheme (data:/blob:/...). ANY other unquoted token names an external
        # source -- a bare host, host:port, IPv6 ([::1]), a single-label host
        # (localhost), a wildcard (*), or a network scheme (http:/https:/ws:/
        # wss:) -- and is flagged. This is an allowlist, so no host form slips.
        # Non-source directives (report-uri, sandbox, trusted-types, ...) are not
        # source lists, so their words are not hosts.
        for name, toks in directives.items():
            if name in _CSP_NON_SOURCE:
                continue
            for tok in toks:
                if tok.startswith("'"):
                    continue
                # A host-free scheme (data:/blob:/...) is allowed everywhere EXCEPT
                # a script directive, where it re-opens arbitrary script execution.
                if tok in _CSP_SAFE_SCHEMES and name not in _CSP_SCRIPT_DIRECTIVES:
                    continue
                failures.append('%s: CSP %s allow-lists an external source: %s'
                                % (rel, name, tok))
        # Inline <script> elements obey script-src-elem, event handlers obey
        # script-src-attr; each falls back to script-src, then default-src
        # ('none'). Any of them permitting 'unsafe-inline' re-opens inline JS.
        def effective(name):
            return directives.get(name, directives.get(
                'script-src', directives.get('default-src', [])))
        if any("'unsafe-inline'" in effective(name)
               for name in ('script-src-elem', 'script-src-attr')):
            failures.append("%s: CSP allows inline script ('unsafe-inline' in "
                            "script-src / script-src-elem / script-src-attr)" % rel)


# A <script> runs its body only when it is a classic or module script (empty
# type, a JavaScript MIME type, or "module"); any other type (application/ld+json,
# text/template, ...) is an inert data block the browser never executes.
_JS_SCRIPT_TYPES = frozenset((
    '', 'module', 'text/javascript', 'application/javascript',
    'text/ecmascript', 'application/ecmascript', 'application/x-javascript',
    'text/jscript',
))
# Attributes whose value is a navigable URL, so a 'javascript:' value executes.
# (A data-* attribute or a code sample carrying the text does not.)
_URL_ATTRS = frozenset((
    'href', 'xlink:href', 'src', 'action', 'formaction', 'data', 'poster',
))


class _InlineJSAudit(_HTMLScopeParser):
    """Flag anything that needs 'unsafe-inline' to run: an executable inline
    <script> (a body with no src attribute), an inline event-handler attribute
    (on*=), or a javascript: URL. All three are blocked once script-src drops
    'unsafe-inline', so the suite fails BEFORE such a page publishes broken."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inline_script = False
        self.handlers = set()
        self.js_url = False
        self._script_depth = 0
        self._script_executable = False

    def _scan_attrs(self, attrs):
        for name, value in attrs:
            if name.startswith('on'):
                self.handlers.add(name)
            if (name in _URL_ATTRS and value
                    and _url_norm(value).startswith('javascript:')):
                self.js_url = True

    def _recurse_srcdoc(self, tag, attrs):
        # srcdoc is a nested document the browser renders; an inline <script>, an
        # on*= handler, or a javascript: URL inside it needs 'unsafe-inline' just
        # the same, so audit it too (nested srcdoc recurses). Runs for both the
        # start-tag and the self-closing <iframe/> form (text/html ignores the /).
        if tag != 'iframe':
            return
        srcdoc = dict(attrs).get('srcdoc')
        if srcdoc:
            sub = _InlineJSAudit()
            sub.feed(srcdoc)
            self.inline_script = self.inline_script or sub.inline_script
            self.handlers |= sub.handlers
            self.js_url = self.js_url or sub.js_url

    def handle_starttag(self, tag, attrs):
        self._scan_attrs(attrs)
        self._recurse_srcdoc(tag, attrs)
        if tag == 'script':
            self._script_depth += 1
            amap = dict(attrs)
            # A src attribute (any value) makes the browser ignore the body.
            has_src = 'src' in amap
            stype = (amap.get('type') or '').strip().lower()
            self._script_executable = (
                not has_src and stype in _JS_SCRIPT_TYPES)

    def handle_endtag(self, tag):
        if tag == 'script' and self._script_depth:
            self._script_depth -= 1

    def handle_data(self, data):
        if self._script_depth and self._script_executable and data.strip():
            self.inline_script = True


def check_no_inline_script(root, failures):
    # Belt to check_csp's braces: even with the right CSP, a leftover inline
    # <script> / on*= / javascript: would just silently stop working. Flag it.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        audit = _InlineJSAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        if audit.inline_script:
            failures.append('%s: inline <script> body -- move it to an external '
                            '.js file (script-src forbids inline)' % rel)
        for name in sorted(audit.handlers):
            failures.append('%s: inline event handler %s= -- bind it in an '
                            'external .js file (script-src forbids inline)'
                            % (rel, name))
        if audit.js_url:
            failures.append('%s: javascript: URL -- script-src forbids inline'
                            % rel)


def check_supply_chain(root, failures):
    # Supply chain: no page may fetch a subresource (script, image, media, style)
    # from an external host or protocol-relative URL -- everything ships
    # self-hosted or inline (data:). External <a> navigation is fine; only loads
    # are flagged.
    def scan(ext, rel):
        # Extractor.loads is the full subresource surface (RESOURCE_ATTR base plus
        # poster/background/svg-href/input-image), computed HTML-aware.
        for tag, attr, value in ext.loads:
            if _is_external(value):
                failures.append('%s: <%s %s> loads an external resource: %s'
                                % (rel, tag, attr, value))
        # srcset candidates are subresource LOADS too (the loads list records only
        # single-URL attrs); Extractor captures srcset HTML-aware (char-refs
        # decoded, unquoted values handled, code-sample text not matched).
        for srcset in ext.srcsets:
            for candidate in srcset.split(','):
                token = candidate.strip().split()
                if token and _is_external(token[0]):
                    failures.append('%s: srcset loads an external resource: %s'
                                    % (rel, token[0]))
        # A <link> whose rel FETCHES a subresource (stylesheet, icon, preload,
        # manifest, ...) is a load; RESOURCE_ATTR excludes all <link> because a
        # rel=canonical is metadata, so classify by rel here.
        for rels, href in ext.link_rels:
            if _is_external(href) and any(r in FETCHING_LINK_RELS for r in rels):
                failures.append('%s: <link rel=%r> loads an external resource: '
                                '%s' % (rel, ' '.join(rels), href))
        # CSS url() and @import (inline style="" attrs + <style> bodies) can load
        # an external image, font, or stylesheet just as a src can.
        for value in _css_external_refs('\n'.join(ext.styles)):
            if _is_external(value):
                failures.append('%s: CSS url()/@import loads an external '
                                'resource: %s' % (rel, value))
        # An <iframe srcdoc> is a whole nested document the browser renders; its
        # own subresource loads are otherwise invisible. Recurse (nested srcdoc
        # included) so a load hidden inside srcdoc is gated like any other.
        for srcdoc in ext.srcdocs:
            sub = Extractor()
            sub.feed(srcdoc)
            scan(sub, rel)

    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        scan(ext, rel)
    # External url() in a standalone .css file is a load too.
    for base_dir, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in files:
            if not name.endswith('.css'):
                continue
            path = os.path.join(base_dir, name)
            crel = os.path.relpath(path, root)
            with open(path, encoding='utf-8') as handle:
                for value in _css_external_refs(handle.read()):
                    if _is_external(value):
                        failures.append('%s: CSS url() loads an external '
                                        'resource: %s' % (crel, value))


# Class names of the layout containers that place cards in a multi-column grid
# (secure-terminal .fg/.shotgrid/.fcols, output-lies .cards/.panes/.steps, the
# generic .grid/.cols). A .issue card inside one of these fills its column; a
# .issue card stacked directly under a full-width .wrap does not -- its prose is
# capped for readability and leaves a wide empty gutter. New grid layouts must
# use one of these class names (or be added here) so the audit can see them.
GRID_CLASSES = frozenset({
    'fg', 'cards', 'grid', 'panes', 'steps', 'shotgrid', 'fcols', 'cols',
})
# Void elements have no end tag, so they must not be pushed on the nesting stack.
VOID_TAGS = frozenset({
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
    'meta', 'param', 'source', 'track', 'wbr',
})
# A card that contains one of these legitimately needs the full width (a code
# block, a data table, a screenshot, an embedded figure); its width is not the
# "prose capped narrower than the box" bug, so such a card is never flagged.
WIDE_TAGS = frozenset({
    'pre', 'table', 'img', 'svg', 'iframe', 'video', 'canvas', 'figure',
})


class LayoutAudit(_HTMLScopeParser):
    """Flag <section>s that stack 2+ prose-only `.issue` cards full-width instead
    of in a grid. A column of full-width prose cards leaves each card much wider
    than the ~74ch text it holds (the "box wider than its text" bug); the fix is
    to wrap them in a grid container so each card is about as wide as its text. A
    card holding a wide element (code/table/image/figure) genuinely needs the
    width and is never counted."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._open = []        # stack of frames for open, non-void tags; each
                               # <section> frame carries its own ungridded count
        self.offenders = []    # (section_id, ungridded_count)

    def _mark_wide(self):
        # The innermost open .issue card genuinely needs its width.
        for frame in reversed(self._open):
            if frame['is_issue']:
                frame['has_wide'] = True
                break

    def handle_starttag(self, tag, attrs):
        if tag in WIDE_TAGS:
            self._mark_wide()
        if tag in VOID_TAGS:
            return
        classes = set((dict(attrs).get('class') or '').split())
        self._open.append({
            'tag': tag,
            'id': dict(attrs).get('id') or '?',
            'is_grid': bool(classes & GRID_CLASSES),
            'is_section': tag == 'section',
            'is_issue': 'issue' in classes,
            # A card is "gridded" when any enclosing element is a grid container.
            'gridded': any(f['is_grid'] for f in self._open),
            'has_wide': False,
            'ungridded': 0,     # cards counted against a <section> land here
        })

    def handle_endtag(self, tag):
        if tag in VOID_TAGS:
            return
        for i in range(len(self._open) - 1, -1, -1):
            if self._open[i]['tag'] != tag:
                continue
            frame = self._open[i]
            if frame['is_issue'] and not frame['gridded'] and not frame['has_wide']:
                # Count against the nearest ENCLOSING <section> (strictly above
                # this card), so a card that is itself a <section class="issue">
                # lands on its parent section, not on its own frame.
                for anc in range(i - 1, -1, -1):
                    if self._open[anc]['is_section']:
                        self._open[anc]['ungridded'] += 1
                        break
            if frame['is_section'] and frame['ungridded'] >= 2:
                self.offenders.append((frame['id'], frame['ungridded']))
            del self._open[i:]
            break

    def finalize(self):
        # A section a browser leaves OPEN to end-of-document (a self-closed
        # <section/> or a missing </section>) never fires handle_endtag, so flush
        # any still-open offending section here -- its cards did close and counted.
        for frame in self._open:
            if frame['is_section'] and frame['ungridded'] >= 2:
                self.offenders.append((frame['id'], frame['ungridded']))


# Image asset hygiene: an image checked into a site but named by NOTHING (no
# page, stylesheet, script, doc or manifest references it) is dead weight that
# accumulates silently -- e.g. screenshots orphaned when the section that showed
# them is deleted. Flag any image whose filename appears in no text source
# anywhere in the tree. The match is intentionally loose (basename substring
# across every text file, README.md included), so it never FALSE-fails an asset
# that is still used -- a logo referenced only from README counts as referenced.
# It reliably catches the real bug (a batch of shots left behind) because those
# names then appear literally nowhere.
IMAGE_EXTS = frozenset({
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.avif', '.svg',
})
# Text sources that can legitimately name an asset: pages, styles, inline or
# external scripts, docs, web manifests, feeds/sitemaps.
_REF_TEXT_EXTS = frozenset({
    '.html', '.htm', '.css', '.js', '.mjs', '.md', '.markdown', '.json',
    '.webmanifest', '.svg', '.xml', '.txt', '.yml', '.yaml',
})


def _referenced(basename, corpus):
    # Match the basename as a WHOLE path token, not a raw substring: a plain
    # `basename in corpus` reports logo.png as referenced merely because
    # osi-logo.png / gnu-logo.png contain the substring "logo.png", masking a
    # genuinely orphaned file. Bounded: not preceded by a name char / dot / dash
    # (a '/' path separator is fine), not followed by a name char / dash, and not
    # by '.<word>' -- so "logo.png.bak" (a different file) does not mask the
    # orphan logo.png, while a prose "logo.png." (sentence period) still counts.
    return re.search(
        r'(?<![\w.-])' + re.escape(basename) + r'(?![\w-])(?!\.\w)',
        corpus) is not None


def check_assets(root, failures):
    images = []
    ref_text = []
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            path = os.path.join(base, name)
            if ext in IMAGE_EXTS:
                images.append(path)
            if ext in _REF_TEXT_EXTS:
                try:
                    with open(path, encoding='utf-8', errors='replace') as handle:
                        ref_text.append(handle.read())
                except OSError:
                    continue
    corpus = '\n'.join(ref_text)
    for image in sorted(images):
        if not _referenced(os.path.basename(image), corpus):
            failures.append('%s: orphaned image -- referenced by no page, style, '
                            'script, doc or manifest; remove it or reference it'
                            % os.path.relpath(image, root))


def check_card_layout(root, failures):
    # Each page's card sections must grid their cards, not stack them full-width.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        audit = LayoutAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        audit.finalize()
        for section_id, count in audit.offenders:
            failures.append(
                '%s: section #%s stacks %d full-width ".issue" cards; wrap them '
                'in a grid (e.g. <div class="fg">) so each card is about as wide '
                'as its text' % (rel, section_id, count))


# A Reproduce box (.repro) must demonstrate the ATTACK in a traditional tool
# (bare cat, plain git diff, a normal paste), so a reader sees the lie fire.
# Piping the payload into a safety/neutralizer tool makes "Reproduce" show the
# DEFENSE instead -- that belongs in the parallel .mitig box. These are the
# neutralizer/inspector tools that must never appear in a .repro command.
SAFETY_TOOLS = (
    'stcatn', 'stcat', 'unicode-show', 'sanitize-string',
    'text-safety-scan-find', 'text-safety-scan', 'git-diff-review',
)


class _ReproToolAudit(_HTMLScopeParser):
    """Collect the `code.cmd` command strings inside every `.repro` box."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._stack = []          # open non-void tags
        self._repro_at = None     # stack index where the current .repro opened
        self._in_cmd = False
        self._buf = []
        self.commands = []        # cmd strings found inside a .repro

    def handle_starttag(self, tag, attrs):
        if tag in VOID_TAGS:
            return
        classes = set((dict(attrs).get('class') or '').split())
        self._stack.append(tag)
        if self._repro_at is None and 'repro' in classes:
            self._repro_at = len(self._stack) - 1
        if self._repro_at is not None and tag == 'code' and 'cmd' in classes:
            self._in_cmd = True
            self._buf = []

    def handle_data(self, data):
        if self._in_cmd:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag in VOID_TAGS:
            return
        if self._in_cmd and tag == 'code':
            self.commands.append(''.join(self._buf))
            self._in_cmd = False
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i] == tag:
                if self._repro_at is not None and i <= self._repro_at:
                    self._repro_at = None
                del self._stack[i:]
                break


def check_repro_raw(root, failures):
    # Reproduce shows the raw attack in a traditional tool; the neutralizer tool
    # belongs in the sibling Mitigation (.mitig) box, never in .repro.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        audit = _ReproToolAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        for cmd in audit.commands:
            for tool in SAFETY_TOOLS:
                if re.search(r'(?<![\w-])' + re.escape(tool) + r'(?![\w-])', cmd):
                    failures.append(
                        '%s: Reproduce box runs the safety tool %r (%s) -- '
                        'reproduce must show the raw attack in a traditional '
                        'tool; move the tool to a Mitigation (.mitig) box'
                        % (rel, tool, cmd.strip()))
                    break


class _HeaderNavAudit(_HTMLScopeParser):
    """The (label, href) list of the FIRST <nav> inside a <header>. Parsed, not
    regex, so an attribute on the nav (<nav aria-label="Main">) no longer drops
    the whole page from the consistency comparison, and a single-quoted href is
    not lost. The home-anchor prefix is normalized (/#x == #x) and class="active"
    is ignored (class is never collected) -- only the link SET, ORDER and targets
    matter."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._header = 0
        self._nav = 0
        self._seen_nav = False
        self._in_a = False
        self._label = []
        self._href = ''
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'header':
            self._header += 1
            return
        if tag == 'nav':
            if self._header and not self._seen_nav:
                self._seen_nav = True
                self._nav = 1
            elif self._nav:
                self._nav += 1
            return
        if self._nav and tag == 'a':
            href = dict(attrs).get('href') or ''
            if href.startswith('/#'):      # /#install (sub-page) == #install (index)
                href = href[1:]
            self._in_a = True
            self._label = []
            self._href = href

    def handle_data(self, data):
        if self._in_a:
            self._label.append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self._in_a:
            self.links.append((''.join(self._label).strip(), self._href))
            self._in_a = False
        elif tag == 'nav' and self._nav:
            self._nav -= 1
        elif tag == 'header' and self._header:
            self._header -= 1

    def result(self):
        return tuple(self.links) if self._seen_nav else None


def _header_nav(markup):
    audit = _HeaderNavAudit()
    audit.feed(markup)
    return audit.result()


def check_nav(root, failures):
    # Every page's top navigation must carry the SAME links, in the same order,
    # pointing at the same targets -- only the active-page highlight differs. This
    # catches a page that drops or reorders a nav item (e.g. a missing "FAQ" or
    # "Plugins" link) -- a whole bug class the other checks never looked at.
    navs = {}
    for page in html_files(root):
        with open(page, encoding='utf-8') as handle:
            nav = _header_nav(handle.read())
        if nav is not None:
            navs[os.path.relpath(page, root)] = nav
    if len(set(navs.values())) <= 1:
        return
    counts: dict[tuple, int] = {}
    for nav in navs.values():
        counts[nav] = counts.get(nav, 0) + 1
    canonical = max(counts, key=counts.__getitem__)  # the most common nav = the baseline
    canonical_labels = [label for label, _ in canonical]
    for rel, nav in sorted(navs.items()):
        if nav == canonical:
            continue
        labels = [label for label, _ in nav]
        missing = [lab for lab in canonical_labels if lab not in labels]
        extra = [lab for lab in labels if lab not in canonical_labels]
        detail = []
        if missing:
            detail.append('missing ' + ', '.join(missing))
        if extra:
            detail.append('extra ' + ', '.join(extra))
        if not detail:
            detail.append('links differ in order or target')
        failures.append('%s: header nav inconsistent with the rest of the site '
                        '(%s)' % (rel, '; '.join(detail)))


def check_toc_complete(root, failures):
    # A page's "On this page" TOC (<nav class="toc">) must list EVERY top-level content
    # section (<section class="cat" id=...>), so a newly added section cannot silently
    # drift out of the page navigation. The zoom-verify screenshots section shipped with a
    # full section but no TOC entry, and nothing caught it -- check_nav only guards the
    # site-wide header nav, and check_links only that a TOC anchor RESOLVES, never that a
    # section is REACHED. Directional: a TOC may also link non-section anchors (rows, sub-
    # headings); only a `.cat` section missing from the TOC is a failure.
    for page in html_files(root):
        with open(page, encoding='utf-8') as handle:
            markup = handle.read()
        toc = re.search(r'<nav\b[^>]*class="[^"]*\btoc\b[^"]*"[^>]*>(.*?)</nav>',
                        markup, re.DOTALL | re.IGNORECASE)
        if not toc:
            continue                       # a page with no on-this-page TOC is exempt
        linked = set(re.findall(r'href="#([^"]+)"', toc.group(1)))
        rel = os.path.relpath(page, root)
        for sect in re.finditer(r'<section\b([^>]*)>', markup, re.IGNORECASE):
            attrs = sect.group(1)
            cls = re.search(r'class="([^"]*)"', attrs)
            if not cls or 'cat' not in cls.group(1).split():
                continue
            sid = re.search(r'id="([^"]+)"', attrs)
            if sid and sid.group(1) not in linked:
                failures.append('%s: section #%s is missing from the on-this-page TOC'
                                % (rel, sid.group(1)))


# --- Forced line breaks in headings -------------------------------------------
# A hard <br> inside a heading forces a wrap point that fights responsive
# reflow: on a narrow phone the heading's first segment already wraps on its own,
# and the <br> then adds ANOTHER line, orphaning a word ("The text on your /
# screen / can lie to you." -- 3 lines, "screen" alone). Headings must wrap
# naturally (CSS text-wrap:balance), never with a hard break. Flagged for h1-h6
# only; a <br> in body prose or a table cell is legitimate and never touched.
_HEADINGS = frozenset({'h1', 'h2', 'h3', 'h4', 'h5', 'h6'})


class _HeadingBreakAudit(_HTMLScopeParser):
    """Count <br> elements that occur while a heading (h1-h6) is open."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._depth = 0          # open heading elements
        self.hits = 0

    def handle_starttag(self, tag, attrs):
        # <br/> self-closing reaches here via the scope-parser mixin (br is void).
        if tag in _HEADINGS:
            self._depth += 1
        elif tag == 'br' and self._depth:
            self.hits += 1

    def handle_endtag(self, tag):
        if tag in _HEADINGS and self._depth:
            self._depth -= 1


def check_heading_breaks(root, failures):
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        audit = _HeadingBreakAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        if audit.hits:
            failures.append(
                '%s: %d hard <br> inside a heading; remove it and let the heading '
                'wrap naturally (CSS text-wrap:balance) so it never orphans a word '
                'on mobile' % (rel, audit.hits))


# --- Color contrast of on-paper text tokens ----------------------------------
# The family's shared color vocabulary: these CSS custom properties are used as
# small text on the light page background (--bg). Each must clear WCAG AA for
# small text (4.5:1) against --bg, or an accent reads washed-out / "off" -- the
# low-contrast red kicker bug (git-diffs-lie --accent #d83933 = 4.12:1). The dark
# terminal palette (--tfg, --tadd, ...) is a SEPARATE vocabulary rendered on a
# dark pane and is deliberately excluded; a token here is checked ONLY when the
# site actually uses it as `color:var(--token)` somewhere (so a token used only
# as a background or border is never judged against the page background).
PAPER_TEXT_TOKENS = frozenset({'accent', 'safe', 'muted', 'ink', 'danger'})
AA_SMALL = 4.5

_ROOT_VAR = re.compile(r'--([\w-]+)\s*:\s*([^;}]+)')
_COLOR_VAR_USE = re.compile(r'color\s*:\s*var\(\s*--([\w-]+)\s*\)', re.IGNORECASE)
_HEX = re.compile(r'^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$')
_RGB = re.compile(r'^rgba?\(([^)]*)\)', re.IGNORECASE)
_HSL = re.compile(r'^hsla?\(([^)]*)\)', re.IGNORECASE)


def _channel(token):
    # An rgb() component: a number 0-255 (CSS Color 4 allows a fractional value),
    # or a percentage of 255.
    token = token.strip()
    if token.endswith('%'):
        return min(255, max(0, round(float(token[:-1]) * 255 / 100)))
    return min(255, max(0, round(float(token))))


def _hue_deg(token):
    # An hsl() hue: a number in deg (default), grad, rad, or turn.
    match = re.match(r'^([+-]?[0-9.]+)(deg|grad|rad|turn)?$', token.strip(),
                     re.IGNORECASE)
    if not match:
        raise ValueError(token)
    value, unit = float(match.group(1)), (match.group(2) or 'deg').lower()
    if unit == 'grad':
        return value * 0.9
    if unit == 'rad':
        return value * 180 / math.pi
    if unit == 'turn':
        return value * 360
    return value


def _hsl_to_rgb(hue, sat, light):
    # HSL (hue in degrees, sat/light as 0..1) -> (r, g, b) 0-255.
    hue = (hue % 360) / 360
    if sat == 0:
        gray = round(light * 255)
        return (gray, gray, gray)
    high = light * (1 + sat) if light < 0.5 else light + sat - light * sat
    low = 2 * light - high

    def component(offset):
        offset %= 1
        if offset < 1 / 6:
            return low + (high - low) * 6 * offset
        if offset < 1 / 2:
            return high
        if offset < 2 / 3:
            return low + (high - low) * (2 / 3 - offset) * 6
        return low
    return (round(component(hue + 1 / 3) * 255),
            round(component(hue) * 255),
            round(component(hue - 1 / 3) * 255))


def _parse_color(value):
    """(r, g, b) for a hex, rgb()/rgba() (integer or %), or hsl()/hsla() color;
    else None (a named color, an unresolved var(), ...). var() indirection is
    resolved by the caller (_resolve_color) before this sees the value."""
    value = value.strip()
    match = _HEX.match(value)
    if match:
        digits = match.group(1)
        if len(digits) == 3:
            digits = ''.join(ch * 2 for ch in digits)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
    match = _RGB.match(value)
    if match:
        parts = [p for p in re.split(r'[\s,/]+', match.group(1).strip()) if p]
        if len(parts) >= 3:
            # OverflowError: an overflowing literal (1e309 -> inf) is unparseable,
            # skipped like any other bad token -- never a crash of the whole gate.
            try:
                return (_channel(parts[0]), _channel(parts[1]), _channel(parts[2]))
            except (ValueError, OverflowError):
                return None
    match = _HSL.match(value)
    if match:
        parts = [p for p in re.split(r'[\s,/]+', match.group(1).strip()) if p]
        if len(parts) >= 3:
            try:
                hue = _hue_deg(parts[0])
                sat = float(parts[1].rstrip('%')) / 100
                light = float(parts[2].rstrip('%')) / 100
            except (ValueError, OverflowError):
                return None
            return _hsl_to_rgb(hue, sat, light)
    return None


def _relative_luminance(rgb):
    def channel(component):
        srgb = component / 255
        return srgb / 12.92 if srgb <= 0.03928 else ((srgb + 0.055) / 1.055) ** 2.4
    red, green, blue = (channel(component) for component in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(fg, bg):
    light = _relative_luminance(fg)
    dark = _relative_luminance(bg)
    hi, lo = max(light, dark), min(light, dark)
    return (hi + 0.05) / (lo + 0.05)


_ROOT_BLOCK = re.compile(r':root\s*\{([^}]*)\}')


def _css_sources(root):
    """Each independent stylesheet scope of a site, as (label, css-text): every
    .css file, plus each page's embedded <style>/style="" bundle. Scopes are kept
    SEPARATE -- a subsite (git-diffs-lie/style.css) carries its own theme with its
    own --bg and --accent, so merging it into the parent's CSS would conflate two
    different color vocabularies (and pick the wrong --accent, last-wins)."""
    # Strip CSS comments at the source: a commented-out :root palette or a `.class`
    # rule left behind in a comment must not read as a live definition (a false
    # contrast pairing, or an undefined class masked as defined).
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in sorted(files):
            if not name.endswith('.css'):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, encoding='utf-8') as handle:
                    yield os.path.relpath(path, root), _strip_css_comments(handle.read())
            except OSError:
                continue
    for page in html_files(root):
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        if ext.styles:
            yield os.path.relpath(page, root), _strip_css_comments('\n'.join(ext.styles))


_VAR_OPEN = re.compile(r'^var\(\s*(.*)\)\s*$', re.DOTALL | re.IGNORECASE)
_VAR_NAME = re.compile(r'^--([\w-]+)$')


def _split_var(value):
    """('--name', fallback-or-None) for a var() expression, else None. Splits on
    the FIRST top-level comma so a fallback carrying nested parens/commas
    (var(--x, rgb(0,0,0))) is preserved intact."""
    match = _VAR_OPEN.match(value.strip())
    if not match:
        return None
    inner, depth = match.group(1), 0
    for i, char in enumerate(inner):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ',' and depth == 0:
            return inner[:i].strip(), inner[i + 1:].strip()
    return inner.strip(), None


def _resolve_color(value, raw, _seen=None):
    """Parse a color, following var() indirection through the :root palette (a
    --accent defined as var(--brand)) and honoring a var() fallback when the
    referenced token is missing, cyclic, or not a color. Cycle-guarded; None if
    nothing in the chain lands on a concrete color."""
    _seen = _seen or set()
    parsed = _split_var(value)
    if parsed is not None:
        primary, fallback = parsed
        name = _VAR_NAME.match(primary)
        if name and name.group(1) not in _seen and name.group(1) in raw:
            resolved = _resolve_color(raw[name.group(1)], raw,
                                      _seen | {name.group(1)})
            if resolved is not None:
                return resolved
        # primary unresolved -> the fallback expression (a browser uses it too)
        return _resolve_color(fallback, raw, _seen) if fallback is not None else None
    return _parse_color(value)


def check_contrast(root, failures):
    # Per stylesheet scope: parse its :root token palette and, when it defines a
    # page background (--bg), check every paper-text token it both defines and
    # uses as text (color:var(--token)) clears WCAG AA for small text.
    for label, css in _css_sources(root):
        raw = {}
        for m in _ROOT_BLOCK.finditer(css):
            # Only the TOP-LEVEL :root palette (the default color scheme). A :root nested
            # inside an at-rule -- e.g. @media (prefers-color-scheme: dark) -- must NOT be
            # merged in: its override (say a dark --bg) would then be contrast-paired with
            # an un-overridden light-mode token (--accent), a cross-color-scheme pairing
            # that never renders together, i.e. a false failure. Top level == balanced
            # braces before the match (same brace-counting the rest of this file tolerates).
            before = css[:m.start()]
            if before.count('{') != before.count('}'):
                continue
            for name, value in _ROOT_VAR.findall(m.group(1)):
                raw[name] = value.strip()      # later definition wins (cascade)
        # Resolve after collecting, so a token defined as var(--other) can follow
        # the reference regardless of definition order.
        props = {}
        for name, value in raw.items():
            rgb = _resolve_color(value, raw)
            if rgb is not None:
                props[name] = rgb
        bg = props.get('bg')
        if bg is None:
            continue                            # scope has no page bg -> cannot judge
        used = {name.lower() for name in _COLOR_VAR_USE.findall(css)}
        for name in sorted(PAPER_TEXT_TOKENS & set(props) & used):
            ratio = _contrast(props[name], bg)
            if ratio < AA_SMALL:
                failures.append(
                    '%s: color token --%s (#%02x%02x%02x) on --bg is %.2f:1, below '
                    'WCAG AA for small text (%.1f:1); darken it'
                    % (label, name, props[name][0], props[name][1],
                       props[name][2], ratio, AA_SMALL))


# --- Undefined "sole" CSS classes -------------------------------------------
# A class that is the ONLY class token on its element and is defined in no
# stylesheet (nor referenced from JS) renders unstyled -- the bug where a hero
# label used class="eyebrow" (undefined) instead of the styled .kicker and lost
# its accent/prompt treatment. Scoped to SOLE classes so a co-class marker
# (`cat faq`, `var x-gnome-terminal`, `zone sandbox`) -- where another class
# supplies the styling -- is NOT flagged; that keeps the check low-noise WITHOUT
# a growing allowlist to maintain. The only entries here are sole-class hooks
# styled by a player/script rather than CSS.
UNDEFINED_CLASS_ALLOWLIST = frozenset({'asplayer', 'ascontrols'})


class _SoleClassAudit(html.parser.HTMLParser):
    """Collect every class that appears as the ONLY class token on some element."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sole = set()

    def handle_starttag(self, tag, attrs):
        value = dict(attrs).get('class')
        if value:
            tokens = value.split()
            if len(tokens) == 1:
                self.sole.add(tokens[0])

    handle_startendtag = handle_starttag


def check_undefined_classes(root, failures):
    css = '\n'.join(text for _label, text in _css_sources(root))  # all .css + inline
    defined = set(re.findall(r'\.(-?[_a-zA-Z][_a-zA-Z0-9-]*)', css))
    js_parts = []
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in files:
            if not name.endswith('.js'):
                continue
            try:
                with open(os.path.join(base, name), encoding='utf-8') as handle:
                    js_parts.append(handle.read())
            except OSError:
                continue
    per_page = {}
    for page in html_files(root):
        with open(page, encoding='utf-8') as handle:
            markup = handle.read()
        # `</script[^>]*>`: an HTML script end tag may carry whitespace OR trailing junk before
        # '>' (`</script >`, `</script bar>`) and still ends the block in a browser; `</script>`
        # or `</script\s*>` would miss those and skip the block's JS in the class audit.
        for block in re.findall(r'<script[^>]*>(.*?)</script[^>]*>', markup, re.S | re.I):
            js_parts.append(block)
        audit = _SoleClassAudit()
        audit.feed(markup)
        per_page[os.path.relpath(page, root)] = audit.sole
    js = '\n'.join(js_parts)
    # `name in js` is a deliberately LOOSE substring test: this check is scoped to
    # be low-noise (never false-fail a real hook), so a class name appearing
    # anywhere in the JS clears it. Tightening to a whole-token match surfaces
    # purely cosmetic dead hooks (an undefined download-link class), which is
    # noise disproportionate to a cosmetic lint -- kept loose on purpose.
    for rel, classes in sorted(per_page.items()):
        for name in sorted(classes):
            if (name not in defined and name not in UNDEFINED_CLASS_ALLOWLIST
                    and name not in js):
                failures.append(
                    '%s: sole class %r has no CSS rule (and no JS use) -- the '
                    'element renders unstyled; define it or use the intended class'
                    % (rel, name))


# --- SEO artifacts: sitemap.xml, robots.txt, favicon.png --------------------
# These are DERIVED from the real content-page set (html_files) and the site's
# canonical host, so they must never be hand-maintained -- a hand-edited sitemap
# silently drifts the moment a page is added or removed. `site-generate` writes
# them; check_seo re-derives and compares, failing the gate on any drift, so a
# stale artifact cannot be published. favicon.png is a raster render of
# favicon.svg; raster bytes are NOT reproducible across librsvg/cairo versions,
# so it is verified STRUCTURALLY (present, valid PNG, expected size) and never
# byte-compared -- a byte gate would false-fail wherever the renderer differs.
FAVICON_SIZE = 512  # px; the raster favicon fallback + apple-touch-icon target

# A 24-byte PNG head: 8-byte signature, then the IHDR chunk (length 13, type,
# width, height). The IEND chunk that closes every valid PNG.
_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
_PNG_IHDR_LEN = b'\x00\x00\x00\x0d'
_PNG_IEND = b'IEND\xaeB\x60\x82'


class _CanonicalParser(html.parser.HTMLParser):
    """First <link rel="canonical"> href, attribute order irrelevant and a
    multi-token rel ('alternate canonical') honored. HTMLParser never fires
    handle_starttag for tags inside an HTML comment, so a commented-out
    canonical is ignored -- which a raw-markup regex cannot do."""

    def __init__(self):
        super().__init__()
        self.href = None

    def handle_starttag(self, tag, attrs):
        if tag != 'link' or self.href is not None:
            return
        amap = dict(attrs)
        rel = (amap.get('rel') or '').lower().split()
        if 'canonical' in rel and amap.get('href'):
            self.href = amap['href']


def seo_host(root):
    """The site's canonical host (e.g. 'example.github.io'), read from
    index.html's <link rel="canonical">, or None if absent/unparseable."""
    try:
        with open(os.path.join(root, 'index.html'), encoding='utf-8') as handle:
            markup = handle.read()
    except OSError:
        return None
    parser = _CanonicalParser()
    parser.feed(markup)
    if not parser.href:
        return None
    return urllib.parse.urlparse(parser.href).netloc or None


def _quote_path(rel):
    # Percent-encode each path segment (a legal filename may hold '#', '&', a
    # space); the '/' separators stay literal.
    return '/'.join(urllib.parse.quote(seg, safe='') for seg in rel.split('/'))


def seo_page_urls(root, host):
    """Sorted absolute URLs for every navigable content page under root. A
    directory index maps to its directory URL ('/', '/sub/'); any other page
    keeps its .html name. Assumes the site is served at the domain root (true
    for every <owner>.github.io Pages site here)."""
    urls = set()
    for page in html_files(root):
        rel = os.path.relpath(page, root).replace(os.sep, '/')
        if rel == 'index.html':
            path = '/'
        elif rel.endswith('/index.html'):
            path = '/' + _quote_path(rel[:-len('/index.html')]) + '/'
        else:
            path = '/' + _quote_path(rel)
        urls.add('https://%s%s' % (host, path))
    return sorted(urls)


def render_sitemap(root, host):
    """The canonical sitemap.xml text for a site (trailing newline included)."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for url in seo_page_urls(root, host):
        # Percent-encoding already removes XML metacharacters from the path;
        # escape defensively so a host or scheme could never inject markup.
        lines.append('  <url><loc>%s</loc></url>' % html.escape(url, quote=False))
    lines.append('</urlset>')
    return '\n'.join(lines) + '\n'


def render_robots(host):
    """The canonical robots.txt text for a site (trailing newline included)."""
    return ('User-agent: *\n'
            'Allow: /\n'
            '\n'
            'Sitemap: https://%s/sitemap.xml\n' % host)


def _png_size(path):
    """(width, height) of a PNG read from its IHDR, or None if the signature or
    IHDR chunk header is malformed."""
    try:
        with open(path, 'rb') as handle:
            header = handle.read(24)
    except OSError:
        return None
    if len(header) < 24 or header[:8] != _PNG_MAGIC \
            or header[8:12] != _PNG_IHDR_LEN or header[12:16] != b'IHDR':
        return None
    return (int.from_bytes(header[16:20], 'big'),
            int.from_bytes(header[20:24], 'big'))


def _png_complete(path):
    """True if the file ends with the PNG IEND chunk. A portable completeness
    check (IEND bytes are version-invariant) that rejects a truncated file
    without decoding pixels -- which is not reproducible across librsvg."""
    try:
        with open(path, 'rb') as handle:
            handle.seek(-len(_PNG_IEND), os.SEEK_END)
            return handle.read() == _PNG_IEND
    except OSError:
        return False


def check_seo(root):
    """SEO drift/structural problems for one site root, or [] when current. A
    directory with no index.html is not a site root and is skipped."""
    problems: list[str] = []
    if not os.path.isfile(os.path.join(root, 'index.html')):
        return problems
    host = seo_host(root)
    if not host:
        problems.append('index.html has no <link rel="canonical">; SEO '
                        'generation needs it to derive the host')
        return problems
    for name, want in (('sitemap.xml', render_sitemap(root, host)),
                       ('robots.txt', render_robots(host))):
        try:
            with open(os.path.join(root, name), encoding='utf-8') as handle:
                have = handle.read()
        except OSError:
            problems.append('%s missing; run site-generate' % name)
            continue
        if have != want:
            problems.append('%s stale (does not match the page set / host); '
                            'run site-generate' % name)
    if os.path.isfile(os.path.join(root, 'favicon.svg')):
        png = os.path.join(root, 'favicon.png')
        size = _png_size(png)
        if size is None or not _png_complete(png):
            problems.append('favicon.png missing, truncated, or not a valid PNG '
                            'while favicon.svg is present; run site-generate')
        elif size != (FAVICON_SIZE, FAVICON_SIZE):
            problems.append('favicon.png is %dx%d, expected %dx%d; run '
                            'site-generate' % (size + (FAVICON_SIZE,
                                                       FAVICON_SIZE)))
    return problems


def check_seo_current(root, failures):
    failures.extend(check_seo(root))


def main():
    roots = [os.path.normpath(r) for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        sys.stderr.write('website-tests: SKIP (no site root found)\n')
        return 77
    by_name = {os.path.basename(r): r for r in roots}
    total = 0
    for root in roots:
        failures: list[str] = []
        # A subsite (git-diffs-lie) verifies its off-mount absolute links against
        # its parent site's checkout when that is also present.
        mount = None
        parent_roots: tuple[str, ...] = ()
        sub = SUBSITES.get(os.path.basename(root))
        if sub:
            parent_name, mount = sub
            if parent_name in by_name:
                parent_roots = (by_name[parent_name],)
        check_links(root, failures, mount, parent_roots)
        check_wording(root, failures)
        check_freshness(root, failures)
        check_footer(root, failures)
        check_banner(root, failures)
        check_csp(root, failures)
        check_no_inline_script(root, failures)
        check_supply_chain(root, failures)
        check_image_format(root, failures)
        check_assets(root, failures)
        check_card_layout(root, failures)
        check_repro_raw(root, failures)
        check_nav(root, failures)
        check_toc_complete(root, failures)
        check_heading_breaks(root, failures)
        check_contrast(root, failures)
        check_undefined_classes(root, failures)
        check_seo_current(root, failures)
        name = os.path.basename(root)
        if failures:
            total += len(failures)
            for item in failures:
                sys.stderr.write('FAIL %s: %s\n' % (name, item))
        else:
            sys.stdout.write('ok %s: links + wording + footer + banner + csp + '
                             'no-inline-js + '
                             'supply-chain + assets + card-layout + repro-raw + '
                             'nav + '
                             'toc-complete + '
                             'heading-breaks + contrast + undefined-classes + '
                             'seo clean\n' % name)
    sys.stdout.write('website-tests: %d failure(s)\n' % total)
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
