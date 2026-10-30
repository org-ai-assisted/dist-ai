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

import base64
import calendar
import datetime
import hashlib
import html.parser
import math
import os
import posixpath
import re
import sys
import urllib.parse

from dist_ai.webcheck import config

# The generated test-results output tree (test-results-site-generate's
# RESULTS_SUBDIR). Every published screenshot lives under a per-run dir and is
# referenced by its run page's <img>, so nothing here needs an orphan exemption.
RESULTS_SUBDIR = 'automated-test-results'

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


class Extractor(html.parser.HTMLParser):
    """Collect (attr) link targets, element ids, and the concatenated visible
    text (script/style excluded) of one HTML document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # (tag, attr, value, navigational) for href/src/data
        self.loads = []          # (tag, attr, value) subresource LOADS (supply-chain)
        self.srcdocs = []        # iframe srcdoc HTML: a nested document to recurse
        self.link_rels = []      # (rel-tokens, href) for every <link href=...>
        self.srcsets = []        # srcset attribute values (char-refs decoded)
        self.ids = set()
        self.text_parts = []
        self.csp = None          # content of the CSP <meta http-equiv>
        self.csp_count = 0       # number of CSP <meta http-equiv> elements seen
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
            self.csp_count += 1
        if tag == 'link' and amap.get('href'):
            self.link_rels.append(
                ((amap.get('rel') or '').lower().split(), amap['href']))
        if amap.get('srcset'):
            self.srcsets.append(amap['srcset'])
        # <object data=...> is a subresource load (RESOURCE_ATTR); capture it so
        # that entry is not dead. Scoped to <object> so a stray data="" attribute
        # on another element is never mistaken for a link.
        if tag == 'object' and amap.get('data'):
            self.links.append((tag, 'data', amap['data'], False))
        for key in ('href', 'src'):
            if key in amap and amap[key] is not None:
                self.links.append(
                    (tag, key, amap[key], _is_navigational(tag, key, amap)))
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


def _abs_candidates(rel, search_roots, navigational=False):
    """Filesystem candidates for a root-absolute path `rel` across search_roots,
    with '..' clamped at each root so a candidate can never escape it (matching
    how a static server serves the path).

    `navigational` gates the `base + '.html'` clean-URL fallback: a browser-
    NAVIGATED reference (<a href>/<area href>, or a curated page URL) is served
    as X.html by GitHub Pages / the wiki generator, so the fallback applies. A
    subresource LOAD (<img>/<script>/<link>/<source> src/href, CSS url()) is
    fetched as-named -- the browser never tries X.html -- so an absent subresource
    with a same-name .html sibling must still read as MISSING, not be masked."""
    # Capture the directory intent BEFORE clamp (posixpath.normpath strips the
    # trailing '/'); also treat a real directory as one even if its name has a
    # dot (a 'blog.v2/' would otherwise look like it has a file extension).
    is_dir = rel == '' or rel.endswith('/')
    rel = _clamp(rel)
    candidates = []
    for sr in search_roots:
        base = os.path.normpath(os.path.join(sr, rel))
        candidates.append(base)
        # A dir-like path serves its index.html; gate stays dir-like (a real
        # index.html implies the dir exists, so os.path.isdir covers it). This
        # applies to EVERY caller, navigational or not.
        if is_dir or os.path.isdir(base):
            candidates.append(os.path.join(base, 'index.html'))
        # GitHub Pages and the wiki generator both serve /X as X.html regardless
        # of a dot in X (a MediaWiki title like 'Apparmor.d' or 'File:Foo.svg'
        # has a false extension) -- but ONLY for a navigated link, never a
        # subresource load (see the docstring). A real file still resolves first
        # -- callers take the first existing candidate.
        if navigational:
            candidates.append(base + '.html')
    return candidates


# A URI scheme at the very start (RFC 3986: ALPHA *( ALPHA / DIGIT / + / - / . )
# then ':'). Matched against the _url_norm (lowercased, control-stripped) form so
# no whitespace/case trick smuggles a scheme past it. '/' is not a scheme char, so
# a relative path's first '/' ends the match before any colon.
_SCHEME_RE = re.compile(r'[a-z][a-z0-9+.-]*:')


def resolve_internal(root, page, target, mount=None, parent_roots=(),
                     navigational=False):
    """Map an internal href/src to a filesystem path candidate list, or None if
    the link is external / a pure fragment / non-navigational. For a subsite,
    `mount` is its path under the parent domain and `parent_roots` are the parent
    site checkouts its off-mount absolute links resolve against.

    `navigational` (a NAVIGATED page reference -- see _is_navigational) gates the
    clean-URL `base + '.html'` fallback: a subresource LOAD must not resolve to a
    same-name .html sibling and so mask a 404'd image/script/stylesheet (see
    _abs_candidates)."""
    # Any leading URI scheme is external / non-navigational (payment URIs like
    # bitcoin:/monero:/ethereum:, magnet:, mailto:/tel:/data:/javascript:, ...).
    # A scheme is letters then letters/digits/+/-/. then a colon, anchored at the
    # start -- so a '/' or '.' before any colon (a relative path like
    # 'wiki/Apparmor.d', a MediaWiki 'File:' link emitted as './File:Foo') breaks
    # the match and stays INTERNAL. http/https// also go through _is_external
    # (covers the '//host' scheme-relative form with no scheme colon).
    if _is_external(target) or _SCHEME_RE.match(_url_norm(target)):
        return None
    frag = ''
    if '#' in target:
        target, frag = target.split('#', 1)
    # A query string (a cache-buster like style.css?v=2) is a valid same-origin
    # URL; the static server ignores it and returns the file, so resolve against
    # the path only. Fragment is split first so path?query#frag keeps its frag.
    if '?' in target:
        target = target.split('?', 1)[0]
    # Decode percent-encoding so the on-disk lookup matches the generator's actual
    # filenames (it percent-encodes emitted href segments); an encoded internal
    # link like 'my%20page.html' otherwise false-fails as a broken link. Decode
    # BEFORE the '..' clamp / urljoin below so an encoded '..' ('%2e%2e') is clamped
    # too, never slipped past it.
    target = urllib.parse.unquote(target)
    # Decode the fragment too (split out above, BEFORE this unquote). A browser
    # percent-decodes #frag and matches it against an element id, which is a literal
    # attribute value never percent-encoded -- so an encoded anchor ('#%74op' = #top,
    # or a non-ASCII heading id) must be decoded here or it false-fails as broken.
    frag = urllib.parse.unquote(frag)
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
                    _abs_candidates(target[len(mnt):].lstrip('/'), [root],
                                    navigational), frag)
        if mount:
            # A subsite's OFF-mount absolute link (/terminal/, /paste/, ...) points
            # at the PARENT site, so verify it ONLY there -- searching the subsite
            # too could let a coincidental child path mask a broken parent link.
            # With no parent checked out it is external / unverifiable, not a fail.
            if not parent_roots:
                return None
            return ('file', _abs_candidates(target.lstrip('/'),
                                            list(parent_roots), navigational), frag)
        if any(target.startswith(prefix) for prefix in KNOWN_PROJECT_PATHS):
            return None                          # valid sibling project-Pages path
        return ('file', _abs_candidates(target.lstrip('/'), [root], navigational), frag)
    # Resolve the relative link as a URL path against the page's own URL,
    # clamping '..' at the site root exactly as a browser does (urljoin drops the
    # leading '..' rather than escaping), then map that in-root path to disk.
    page_url = '/' + os.path.relpath(page, root).replace(os.sep, '/')
    resolved = urllib.parse.urljoin(page_url, target)
    base = os.path.normpath(os.path.join(root, _clamp(resolved.lstrip('/'))))
    candidates = [base]
    # index.html only for a dir-like path (a real index.html implies the dir
    # exists); the .html fallback is navigational-only (see _abs_candidates: /X is
    # served as X.html even when X has a dot, but ONLY for a navigated link).
    if target.endswith('/') or resolved.endswith('/') or os.path.isdir(base):
        candidates.append(os.path.join(base, 'index.html'))
    # Clean-URL .html fallback: navigated links only (see _abs_candidates) -- a
    # subresource load must not be masked by a same-name .html sibling.
    if navigational:
        candidates.append(base + '.html')
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


def check_links(root, failures, mount=None, parent_roots=(), pages=None):
    # Audit the links OF `pages` (every page when None; a curated subset under the
    # wiki policy), resolving each target against the WHOLE tree on disk -- so a
    # restricted audit still validates links that point at un-audited pages.
    # Preload ids per audited page for same-tree fragment checks.
    loaded = {}
    for page in (html_files(root) if pages is None else pages):
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        loaded[os.path.normpath(page)] = ext
    for page, ext in loaded.items():
        rel = os.path.relpath(page, root)
        for _tag, _attr, value, navigational in ext.links:
            # `navigational` (set by the Extractor, rel-aware for <link>) gates the
            # clean-URL X.html fallback: a navigated page reference gets it, a
            # subresource load (img/script/stylesheet/source/object) does not, so a
            # missing load is never masked by a same-name .html sibling.
            resolved = resolve_internal(root, page, value, mount, parent_roots,
                                        navigational)
            if resolved is None:
                continue
            if resolved[0] == '#self':
                frag = resolved[2]
                # 'top' (ASCII case-insensitive) and the empty fragment are HTML special
                # fragments: with no matching id/name the indicated part is the top of the
                # document, so they ALWAYS resolve and are never a broken anchor. (The empty
                # fragment is already falsy below; 'top' is the one needing an explicit pass.)
                if frag and frag.lower() != 'top' and frag not in ext.ids:
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
            # 'top' (ASCII case-insensitive) is an HTML special fragment on ANY
            # page: with no matching id/name it still scrolls to the document top,
            # so it ALWAYS resolves and is never a broken anchor -- on a cross-page
            # / other-page target exactly as on the same-page (#self) branch above.
            # (The empty fragment is already excluded by the enclosing `if frag`.)
            if frag and frag.lower() != 'top':
                # The target may live in a PARENT site (a subsite's cross-site
                # link) or an un-audited page, neither preloaded in `loaded`; load
                # its ids on demand so a missing cross-site anchor is caught, not
                # silently accepted.
                target_ids = loaded[hit].ids if hit in loaded else _ids_of(hit)
                if target_ids is not None and frag not in target_ids:
                    failures.append('%s: link %r targets missing #%s'
                                    % (rel, value, frag))


def check_wording(root, failures, pages=None):
    for page in (html_files(root) if pages is None else pages):
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


class _FooterAudit(html.parser.HTMLParser):
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

    def handle_startendtag(self, tag, attrs):
        # A browser ignores the '/' on a non-void <footer/> and leaves it OPEN, so
        # the family links that follow are still its children. Treat a self-closing
        # tag as a plain start (never auto-close) so the old regex's whole-tail
        # behavior on a <footer/> is preserved. Only <footer> drives depth, so a
        # self-closed leaf inside the footer just contributes its attrs.
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self._depth:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == 'footer' and self._depth:
            self._depth -= 1

    def scope(self):
        return ' '.join(self._buf).lower()


def check_footer(root, failures, require_family_links=True, pages=None):
    # EVERY page must HAVE a footer (the top-level index at minimum), and -- under the
    # family policy -- every footer must carry all FAMILY links (the uniform chrome puts
    # a footer on every page, INCLUDING generated subpages). The csr policy passes
    # require_family_links=False: the CSR site is deliberately vendor-neutral (NOT in
    # FAMILY), so injecting the project family links would undermine its independence;
    # its own footer nav is checked for presence + consistency by check_footer_nav
    # instead. The footer-EXISTS check and check_footer_structure apply to both.
    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        with open(page, encoding='utf-8') as handle:
            markup = handle.read()
        audit = _FooterAudit()
        audit.feed(markup)
        if not audit.saw:
            if rel == 'index.html':
                failures.append('index.html: no <footer>')
            continue
        if not require_family_links:
            continue
        # Check the family links against the union of ALL <footer> regions: content
        # AFTER a footer must not mask a missing link (the whole-tail bug), and an
        # earlier <article>/<section> footer must not hide the site footer.
        scope = audit.scope()
        for _name, url in FAMILY.items():
            if url not in scope:
                failures.append('%s: footer missing family link %s' % (rel, url))


# <footer> rows styled with their own horizontal gutter + centered max-width in the
# shared stylesheet. Each is a DIRECT child of <footer>; nesting one inside an extra
# wrapper (e.g. a lone <div class="wrap">) double-applies the gutter and shoves the
# row out of line with its siblings -- the broken-footer bug the browser guard
# (check_footer.py) could not see once a single wrapper collapsed <footer> to one
# child. These classes are style.css footer-row selectors, kept in sync with it.
FOOTER_ROW_CLASSES = frozenset(('ftop', 'fbot', 'fshare', 'ffree'))

# Void elements have no end tag, so they must never be pushed onto the parent stack
# (an <img> left on the stack would mis-parent the row that follows it).
_VOID_ELEMENTS = frozenset((
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
    'param', 'source', 'track', 'wbr',
))


class _FooterStructure(html.parser.HTMLParser):
    """Flag any footer row (.ftop/.fbot/.fshare/.ffree) that is NOT a direct child
    of a <footer>. Parsed, not regex, so attribute quoting and nesting are handled
    uniformly with the other audits; a row inside an HTML comment is invisible."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._stack = []          # open, non-void element tags, outermost first
        self.offenders = set()    # row classes nested below a direct <footer> child

    def _flag_if_indirect(self, attrs):
        # A footer row misplaced <=> we are inside a footer but its immediate parent
        # (top of the open-element stack) is not the <footer> itself.
        if 'footer' not in self._stack:
            return
        hit = set((dict(attrs).get('class') or '').split()) & FOOTER_ROW_CLASSES
        if hit and (not self._stack or self._stack[-1] != 'footer'):
            self.offenders |= hit

    def handle_starttag(self, tag, attrs):
        self._flag_if_indirect(attrs)
        if tag not in _VOID_ELEMENTS:
            self._stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        # A self-closing tag is a childless leaf: run the class check, never push it.
        self._flag_if_indirect(attrs)

    def handle_endtag(self, tag):
        if tag in _VOID_ELEMENTS:
            return
        # Pop to the nearest matching open tag (tolerates an unclosed inner element
        # the same way a browser recovers), so parent tracking stays correct.
        if tag in self._stack:
            while self._stack:
                if self._stack.pop() == tag:
                    break


def check_footer_structure(root, failures):
    for page in html_files(root):
        audit = _FooterStructure()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        rel = os.path.relpath(page, root)
        for cls in sorted(audit.offenders):
            failures.append('%s: footer .%s is not a direct <footer> child -- a nested '
                            'row double-applies the gutter and misaligns it' % (rel, cls))


class _StatusPillAudit(html.parser.HTMLParser):
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


def _is_navigational(tag, attr, amap):
    """True when an href/src is a NAVIGATED page reference (so the clean-URL
    X.html fallback applies), False when it is a subresource LOAD (fetched
    as-named -- a missing one must read as broken, never be masked by a same-name
    .html sibling). <a>/<area> href navigate. An <iframe>/<frame> src loads a
    browsing-context DOCUMENT (not a resource like img/script), so its clean-URL
    .html form resolves just like a navigation. A <link> href names a page URL
    (canonical, alternate, prev/next, ...) UNLESS its rel fetches a subresource
    (stylesheet/icon/preload/...), which is a LOAD. Every other src/href/data
    (img/script/source/embed/audio/video/track src, <object> data) is a load."""
    if (tag, attr) in (('a', 'href'), ('area', 'href'),
                       ('iframe', 'src'), ('frame', 'src')):
        return True
    if tag == 'link' and attr == 'href':
        rels = set((amap.get('rel') or '').lower().split())
        return not (rels & FETCHING_LINK_RELS)
    return False

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


# @import loads a stylesheet in both a bare-string form (@import "url";) and a
# url() form (@import url(...)); match both. The url() form is ALSO caught by
# _css_urls, but only when its ')' is present -- an unclosed @import url("..." at
# end-of-stylesheet is a parse error a browser still fetches, so keep the url(
# branch here to catch it, and de-duplicate by value below so a well-formed
# @import url() is reported once, not twice.
_CSS_IMPORT = re.compile(
    r"""@import\s+(?:url\(\s*)?["']?([^"')\s;]+)""", re.IGNORECASE)


def _css_external_refs(text):
    text = _strip_css_comments(text)
    seen = set()
    for ref in _css_urls(text):
        seen.add(ref)
        yield ref
    for match in _CSS_IMPORT.finditer(text):
        ref = match.group(1)
        if ref not in seen:            # already yielded as a url() by _css_urls
            yield ref
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


def _is_wiki_namespace_page(url):
    # A MediaWiki File:/Image: namespace link (<a href="./File:Etcher1.png">)
    # resolves to an HTML description page (wiki/File:Etcher1.png.html), NOT a
    # raster -- the trailing ".png" is part of the wiki page TITLE, not a file
    # extension. Only the <a href> clause consults this; a real <img src="x.png">
    # is still flagged. Family sites have no File:/Image: links, so this is a
    # harmless no-op there.
    seg = urllib.parse.unquote(url.split('#', 1)[0].split('?', 1)[0])
    seg = seg.rsplit('/', 1)[-1]
    return seg.startswith(('File:', 'Image:'))


def _raster_target(ref_dir, value, root):
    # Resolve a raster reference to the file it points at, so the SAME image reached
    # from many pages (a footer logo) or named twice on one page collapses to one
    # failure. A root-absolute ref (/logo.png) resolves against the SITE ROOT, a
    # relative ref against the referencing file's directory -- so both forms of the
    # same deployed file (/logo.png and logo.png at the root) collapse to ONE key,
    # not two (mirrors resolve_internal's root-absolute vs relative split). URL path
    # semantics. ref_dir/root are filesystem paths; posixpath keys them consistently.
    path = urllib.parse.unquote(value.split('#', 1)[0].split('?', 1)[0])
    base = root if path.startswith('/') else ref_dir
    return posixpath.normpath(posixpath.join(base, path.lstrip('/')))


def check_image_format(root, failures, pages=None):
    # Content raster references must be webp (except the static allowlist). Covers
    # <img>/<source> src, srcset candidates, <a href> to a raster, and CSS url()
    # in a .css file or an inline/embedded style.
    # Dedup by resolved target file: the same raster reached from every page (a
    # footer logo) or named twice on one page is ONE failure, not N identical lines.
    seen: set[str] = set()

    def report(ref_dir, value, message):
        target = _raster_target(ref_dir, value, root)
        if target in seen:
            return
        seen.add(target)
        failures.append(message)

    def scan(ext, rel, ref_dir):
        for tag, attr, value, _navigational in ext.links:
            # Only the site's OWN rasters can be converted; an external URL is a
            # supply-chain concern (gated there), not a must-be-webp target.
            if _is_external(value):
                continue
            # An <a href> ending in .png/.jpg is a content raster EXCEPT a MediaWiki
            # File:/Image: namespace link, which is a title that resolves to an HTML
            # description page, not an image.
            a_raster = (tag == 'a' and attr == 'href' and _is_raster(value)
                        and not _is_wiki_namespace_page(value))
            content = (tag in ('img', 'source') and attr == 'src') or a_raster
            if content and _is_raster(value) and not _allowed_raster(value):
                report(ref_dir, value,
                       '%s: content image %r must be webp (convert with '
                       'site-image-optimize)' % (rel, value))
        for srcset in ext.srcsets:
            for candidate in srcset.split(','):
                token = candidate.strip().split()
                if token and _is_raster(token[0]) and not _is_external(token[0]) \
                        and not _allowed_raster(token[0]):
                    report(ref_dir, token[0],
                           '%s: srcset image %r must be webp' % (rel, token[0]))
        for value in _css_external_refs('\n'.join(ext.styles)):
            if _is_raster(value) and not _allowed_raster(value):
                report(ref_dir, value,
                       '%s: CSS url() image %r must be webp' % (rel, value))
        # A raster inside an <iframe srcdoc> is a content image too; recurse
        # (nested srcdoc included), consistent with supply-chain/inline-script.
        for srcdoc in ext.srcdocs:
            sub = Extractor()
            sub.feed(srcdoc)
            scan(sub, rel, ref_dir)

    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        scan(ext, rel, os.path.dirname(page))
    # Standalone .css files are a site-wide (not per-page) resource: always scanned
    # whole-tree, even for a restricted page audit -- there are only a handful.
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
                    report(base_dir, value,
                           '%s: CSS url() image %r must be webp' % (rel, value))


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


# CSP whitespace is ASCII only (space/tab/CR/LF/FF per the CSP grammar). Tokenize
# on THIS set, not Python str.split() which also splits on Unicode whitespace
# (U+00A0, ...): a token joined to the directive name by non-ASCII whitespace is
# NOT a separate source expression, so a `script-src<U+00A0>'sha256-...'` does not
# parse as a valid script-src and the inline script stays flagged.
_CSP_WS_RE = re.compile(r'[ \t\r\n\f]+')


def _csp_tokens(part):
    return [tok for tok in _CSP_WS_RE.split(part) if tok]


def _csp_directives(csp):
    # CSP is ';'-separated directives; each is a whitespace-separated name then
    # its source tokens. Return {lower-name: [tokens]}. The directive NAME is
    # case-insensitive (folded); source TOKENS keep their case, because a
    # hash-source base64 ('sha256-...') is case-SENSITIVE and folding it would
    # corrupt the digest -- callers that want case-folded tokens lowercase the
    # CSP string themselves before calling. A repeated directive is ignored by
    # the browser after its FIRST occurrence, so keep the first (setdefault) --
    # matching what the page actually enforces.
    out: dict[str, list[str]] = {}
    for part in csp.split(';'):
        toks = _csp_tokens(part)
        if toks:
            out.setdefault(toks[0].lower(), toks[1:])
    return out


def check_csp(root, failures, pages=None):
    # Every page must carry a strict CSP: default-src 'none', no external host
    # allow-listed, and scripts confined to same-origin files -- script-src must
    # NOT permit 'unsafe-inline'. That is what lets every inline <script> move to
    # an external .js and keeps the policy nonce-free and hash-free.
    for page in (html_files(root) if pages is None else pages):
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
        # form-action does NOT fall back to default-src either, so without it a <form>
        # can POST to any origin (data exfiltration / phishing redirect). Require it
        # restricted to 'none'/'self' -- the emitted family policy already carries 'none'.
        if directives.get('form-action') not in (["'none'"], ["'self'"]):
            failures.append("%s: CSP form-action is not 'none'/'self' (a <form> can "
                            "submit to an external origin)" % rel)
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


def check_csr_csp(root, failures):
    # CSR-site-only, ON TOP of the generic check_csp. The site ships one self-hosted
    # Trusted-Types-safe bundle (assets/site.js), so its CSP relaxes script-src to 'self'
    # (NOT 'none') but stays hardened: no 'unsafe-inline'/'unsafe-eval' anywhere, and
    # Trusted Types ENFORCED (require-trusted-types-for 'script'). Assert that stronger shape
    # so a later loosening fails here.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        if ext.csp is None:
            continue              # a missing CSP meta is already a check_csp failure
        directives = _csp_directives(ext.csp.lower())
        if directives.get('script-src') != ["'self'"]:
            failures.append("%s: CSR CSP script-src must be 'self' (got %s)"
                            % (rel, directives.get('script-src')))
        for name, toks in directives.items():
            if "'unsafe-inline'" in toks or "'unsafe-eval'" in toks:
                failures.append("%s: CSR CSP %s permits unsafe-inline/unsafe-eval" % (rel, name))
        if "'script'" not in directives.get('require-trusted-types-for', []):
            failures.append("%s: CSR CSP missing require-trusted-types-for 'script'" % rel)


# Required head metadata for a CSR-policy page (the "perfect SEO" bar:
# exhaustive SEO + social card + JSON-LD + full icon set + PWA manifest). Each is
# a substring the generator emits in the head. Enforced ONLY for the csr
# policy -- the family sites are a separate site group not yet rolled onto the
# JSON-LD/manifest bar, the approved per-site-group opt-out.
_CSR_REQUIRED_META = (
    ('<link rel="canonical"', 'canonical link'),
    ('name="description"', 'meta description'),
    ('property="og:title"', 'og:title'),
    ('property="og:type"', 'og:type'),
    ('property="og:url"', 'og:url'),
    ('property="og:image"', 'og:image'),
    ('property="og:locale"', 'og:locale'),
    ('name="twitter:card"', 'twitter:card'),
    ('name="twitter:image"', 'twitter:image'),
    ('application/ld+json', 'JSON-LD block'),
    ('rel="icon"', 'favicon link'),
    ('rel="apple-touch-icon"', 'apple-touch-icon'),
    ('rel="mask-icon"', 'mask-icon'),
    ('name="theme-color"', 'theme-color meta'),
    ('rel="manifest"', 'PWA manifest link'),
)


def check_page_metadata(root, failures):
    """Every CSR-policy page must carry the full SEO + social + JSON-LD +
    icon + PWA head set. Locks in the perfect-SEO bar so a regression (a new page
    type missing OG, JSON-LD, the manifest link, ...) fails the suite. The
    ephemeral results plane is exempt (it is not a navigable content page)."""
    for page in html_files(root):
        rel = os.path.relpath(page, root).replace(os.sep, '/')
        if rel == RESULTS_SUBDIR or rel.startswith(RESULTS_SUBDIR + '/'):
            continue
        with open(page, encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        # Scan the <head> ONLY: a required tag's substring appearing in body or
        # code-sample text (e.g. a displayed `application/ld+json` snippet) must
        # not satisfy the check -- the tag has to be a real head element.
        head = text.split('</head>', 1)[0]
        for needle, label in _CSR_REQUIRED_META:
            if needle not in head:
                failures.append('%s: missing %s (CSR perfect-SEO bar)'
                                % (rel, label))


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

# A CSP hash-source token: 'sha256-<base64>' (sha256/sha384/sha512). The algorithm
# part is case-insensitive per CSP3; the base64 digest is case-SENSITIVE, so the
# token must reach here with its case intact (see _csp_directives). The digest may
# be standard base64 (+ and /) OR base64url (- and _); browsers normalize -/_ to
# +/, so both alphabets are accepted here and canonicalized to standard base64
# before comparison (see _csp_script_elem_hashes).
_CSP_HASH_RE = re.compile(
    r"^'(sha(?:256|384|512))-([A-Za-z0-9+/_-]+={0,2})'$", re.IGNORECASE)
# Fold a base64url digest onto the standard-base64 alphabet our computed digest
# uses: '-' -> '+', '_' -> '/'.
_CSP_HASH_B64URL = str.maketrans('-_', '+/')


def _csp_script_elem_hashes(csp):
    """Normalized {'sha256-<b64>', ...} hash-sources that govern an inline
    <script> ELEMENT: the effective script-src-elem list (script-src-elem, else
    script-src, else default-src). Parsed from the RAW CSP so the base64 keeps
    its case. A base64url digest is canonicalized to standard base64 so it still
    matches our standard-base64 computed digest (_inline_script_hashes)."""
    directives = _csp_directives(csp)
    sources = directives.get('script-src-elem', directives.get(
        'script-src', directives.get('default-src', [])))
    hashes = set()
    for tok in sources:
        match = _CSP_HASH_RE.match(tok)
        if match:
            hashes.add('%s-%s' % (match.group(1).lower(),
                                  match.group(2).translate(_CSP_HASH_B64URL)))
    return hashes


def _inline_script_hashes(body):
    # The CSP hash is base64(digest(exact script text)), prefixed by the algo.
    # Return all three so a match against any CSP-listed algorithm exempts it.
    data = body.encode('utf-8')
    return {'%s-%s' % (algo, base64.b64encode(
        hashlib.new(algo, data).digest()).decode('ascii'))
        for algo in ('sha256', 'sha384', 'sha512')}


class _InlineJSAudit(html.parser.HTMLParser):
    """Flag anything that needs 'unsafe-inline' to run: an executable inline
    <script> (a body with no src attribute), an inline event-handler attribute
    (on*=), or a javascript: URL. All three are blocked once script-src drops
    'unsafe-inline', so the suite fails BEFORE such a page publishes broken."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        # (body, csp_seen) per executable inline <script>: csp_seen is whether a
        # CSP <meta> preceded the script in document order (a meta-CSP governs only
        # content AFTER it, so a script BEFORE it is unprotected and never hash-exempt).
        self.inline_scripts = []
        self.handlers = set()
        self.js_url = False
        self._csp_seen = False
        self._script_depth = 0
        self._script_executable = False
        self._script_csp_seen = False
        self._script_body = []

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
            self.inline_scripts += sub.inline_scripts
            self.handlers |= sub.handlers
            self.js_url = self.js_url or sub.js_url

    def handle_starttag(self, tag, attrs):
        self._scan_attrs(attrs)
        self._recurse_srcdoc(tag, attrs)
        if tag == 'meta' and (dict(attrs).get('http-equiv') or '').lower() \
                == 'content-security-policy':
            self._csp_seen = True
        if tag == 'script':
            self._script_depth += 1
            amap = dict(attrs)
            # A src attribute (any value) makes the browser ignore the body.
            has_src = 'src' in amap
            stype = (amap.get('type') or '').strip().lower()
            self._script_executable = (
                not has_src and stype in _JS_SCRIPT_TYPES)
            # Snapshot CSP-seen at the START tag: the script's position relative
            # to the meta is what decides whether the meta-CSP governs it.
            self._script_csp_seen = self._csp_seen
            self._script_body = []

    def handle_endtag(self, tag):
        if tag == 'script' and self._script_depth:
            self._script_depth -= 1
            # Capture the EXACT text between <script> and </script> (HTMLParser
            # delivers script content raw, un-char-ref-decoded), so a CSP
            # hash-source can be matched against it. A whitespace-only body runs
            # nothing, so it is not recorded.
            body = ''.join(self._script_body)
            if self._script_executable and body.strip():
                self.inline_scripts.append((body, self._script_csp_seen))
            self._script_body = []

    def handle_data(self, data):
        if self._script_depth and self._script_executable:
            self._script_body.append(data)


def check_no_inline_script(root, failures, pages=None):
    # Belt to check_csp's braces: even with the right CSP, a leftover inline
    # <script> / on*= / javascript: would just silently stop working. Flag it.
    # Exception: an inline <script> BODY the page's own CSP pins by hash
    # (script-src 'sha256-...') is ALLOWED to execute, so it is flagged only when
    # none of its hashes is in the effective script-src-elem hash set. A plain
    # hash does NOT cover an on*= handler or a javascript: URL (those need
    # 'unsafe-hashes'), so those stay flagged unconditionally.
    #
    # The hash exemption assumes the SINGLE well-formed head-level CSP meta our
    # generator emits (mw-static-generator): exactly ONE
    # <meta http-equiv=content-security-policy>, with the inline <script> AFTER it
    # in document order. Any other shape forfeits the exemption (the script is
    # flagged), erring toward flagging so a generator CSP bug is caught:
    #   - MORE than one CSP meta: a browser enforces ALL policies (their
    #     intersection), but the extractor models only one, so honoring a single
    #     hash would be a false-green -> no exemption;
    #   - a script BEFORE the CSP meta: the meta-CSP does not apply to content
    #     preceding it, so such a script is unprotected -> no exemption.
    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        audit = _InlineJSAudit()
        with open(page, encoding='utf-8') as handle:
            content = handle.read()
        ext.feed(content)
        audit.feed(content)
        single_csp = ext.csp is not None and ext.csp_count == 1
        csp_hashes = _csp_script_elem_hashes(ext.csp) if single_csp else set()
        for body, csp_seen in audit.inline_scripts:
            exempt = (single_csp and csp_seen
                      and not _inline_script_hashes(body).isdisjoint(csp_hashes))
            if not exempt:
                failures.append(
                    '%s: inline <script> body -- move it to an external .js '
                    'file or pin it with a CSP script-src hash '
                    '(script-src forbids inline)' % rel)
        for name in sorted(audit.handlers):
            failures.append('%s: inline event handler %s= -- bind it in an '
                            'external .js file (script-src forbids inline)'
                            % (rel, name))
        if audit.js_url:
            failures.append('%s: javascript: URL -- script-src forbids inline'
                            % rel)


class _FoucAudit(html.parser.HTMLParser):
    # FOUC (flash of unstyled content): a render-blocking stylesheet in <head>
    # paints the page styled on the first frame. The patterns that defeat that and
    # flash raw HTML first:
    #   - an onload handler on a stylesheet <link> (the media="print"
    #     onload="this.media='all'" async-apply trick);
    #   - the preload swap: <link rel="preload" as="style" onload="...rel='stylesheet'">
    #     -- the canonical async-CSS pattern (applied only once onload fires);
    #   - a stylesheet <link>, or a <style> element, in <body> (applied late).
    # A JS-INJECTED stylesheet is already blocked by the CSP + no-inline-script gates.
    # Guards: a <body> seen inside <title>/<textarea> (HTMLParser, unlike a real HTML
    # parser, does NOT treat those as RCDATA, so a title containing "<body>" would
    # else flip in_body and false-flag the head sheet); content inside <template> is
    # inert (not applied until cloned), so links/styles there are not flagged.
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_body = False
        self._rcdata = 0         # inside <title>/<textarea> (tags there are not real)
        self._template = 0       # inside <template> (inert content)
        self.async_css = []      # hrefs of async-applied stylesheet links (onload swap)
        self.body_css = []       # hrefs of stylesheet links inside <body>
        self.body_style = 0      # count of <style> elements inside <body>

    def handle_starttag(self, tag, attrs):
        if tag in ('title', 'textarea'):
            self._rcdata += 1
            return
        if tag == 'template':
            self._template += 1
            return
        # Ignore a <body> emitted inside RCDATA text (e.g. a title mentioning it).
        if tag == 'body' and self._rcdata == 0:
            self.in_body = True
            return
        if self._template:       # inert template content is never applied
            return
        if tag == 'style' and self.in_body:
            self.body_style += 1
            return
        if tag != 'link':
            return
        amap = dict(attrs)       # HTMLParser lowercases tag + attribute names
        rels = (amap.get('rel') or '').lower().split()
        href = amap.get('href') or '(no href)'
        is_sheet = 'stylesheet' in rels
        # The preload swap applies CSS only from onload -> an unstyled flash first.
        is_preload_style = 'preload' in rels and (amap.get('as') or '').lower() == 'style'
        if 'onload' in amap and (is_sheet or is_preload_style):
            self.async_css.append(href)
        if is_sheet and self.in_body:
            self.body_css.append(href)

    def handle_endtag(self, tag):
        if tag in ('title', 'textarea') and self._rcdata:
            self._rcdata -= 1
        elif tag == 'template' and self._template:
            self._template -= 1


def check_fouc(root, failures, pages=None):
    # Flash-of-unstyled-content guard: every stylesheet must load render-blocking in
    # <head>. Deterministic + static -- no timing/throttle flake. (A throttled-load
    # frame check is vacuous here: these sites ship external CSS, so ANY async/late
    # delivery flashes; the delivery pattern is what to gate, and it is static.)
    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        audit = _FoucAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        for href in audit.async_css:
            failures.append('%s: stylesheet <link href=%r> is applied via onload '
                            '(async/preload-swap CSS flashes unstyled content) -- load '
                            'it render-blocking in <head>' % (rel, href))
        for href in audit.body_css:
            failures.append('%s: stylesheet <link href=%r> is in <body> (applied late, '
                            'flashes unstyled content) -- move it to <head>'
                            % (rel, href))
        if audit.body_style:
            failures.append('%s: <style> element in <body> (applied when the parser '
                            'reaches it, flashes unstyled content) -- move it to <head>'
                            % rel)


def check_supply_chain(root, failures, pages=None):
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

    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        scan(ext, rel)
    # Standalone .css files are a site-wide resource (a handful of files): always
    # scanned whole-tree, even for a restricted page audit.
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


class LayoutAudit(html.parser.HTMLParser):
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


# Rasters PIL decodes reliably (avif needs a plugin; .ico is multi-size; .svg is handled
# by webcheck.svg_safety) -- integrity-checked by decoding the actual bytes.
RASTER_DECODE_EXTS = frozenset({'.png', '.jpg', '.jpeg', '.gif', '.webp'})


def _page_raster_files(root, pages):
    """The on-disk raster files (RASTER_DECODE_EXTS) that `pages` reference,
    resolved against the full tree with resolve_internal -- the SAME resolver
    check_links uses, so the two never drift. Scopes the raster-integrity decode to
    a curated wiki audit's pages instead of the whole image tree (thousands of
    images, irrelevant to the pages under audit)."""
    found: set[str] = set()

    def consider(page, value):
        # resolve_internal returns None for an external / non-navigational ref, so an
        # external image URL never reaches disk here; keep only resolved rasters.
        resolved = resolve_internal(root, page, value)
        if not resolved or resolved[0] != 'file':
            return
        hit = next((c for c in resolved[1] if os.path.isfile(c)), None)
        if hit and os.path.splitext(hit)[1].lower() in RASTER_DECODE_EXTS:
            found.add(os.path.normpath(hit))

    for page in pages:
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        for _tag, _attr, value, _navigational in ext.links:
            consider(page, value)
        for _tag, _attr, value in ext.loads:
            consider(page, value)
        for srcset in ext.srcsets:
            for candidate in srcset.split(','):
                token = candidate.strip().split()
                if token:
                    consider(page, token[0])
        for value in _css_external_refs('\n'.join(ext.styles)):
            consider(page, value)
    # A raster referenced only from a site-wide stylesheet (a CSS url() background)
    # ships on every page that links the sheet, so it is in scope for a curated wiki
    # audit even though no audited PAGE inlines it. CSS is a handful of site-wide
    # sheets (mirrors _css_sources' whole-tree read); a url() is relative to the CSS
    # file's own directory, so resolve each against the sheet's path, not a page's.
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in sorted(files):
            if not name.endswith('.css'):
                continue
            css_path = os.path.join(base, name)
            try:
                with open(css_path, encoding='utf-8') as handle:
                    css_text = handle.read()
            except OSError:
                continue
            for value in _css_external_refs(css_text):
                consider(css_path, value)
    return found


def check_asset_integrity(root, failures, pages=None):
    # A referenced image can exist and serve HTTP 200 yet be TRUNCATED or corrupt (a
    # botched convert, a partial write, an unexpanded LFS pointer) -- the extension/ref
    # checks, and often a browser's console, do not flag it. Decode every raster's BYTES
    # and require nonzero dimensions, so a broken image cannot publish. PIL is imported
    # lazily: only the family static lane needs it, so mw-static (no PIL dep) can still
    # import the other checks from this module.
    #   pages is None  -> every raster in the tree (family/csr: a small tree, and an
    #                     unreferenced-but-corrupt image is still a publish defect).
    #   pages a list   -> only the rasters THOSE pages reference (a curated wiki audit:
    #                     the tree holds thousands of images, but only the audited
    #                     pages' images are in scope).
    from PIL import Image
    if pages is None:
        paths = []
        for base, dirs, files in os.walk(root):
            _prune_git(dirs)
            for name in sorted(files):
                if os.path.splitext(name)[1].lower() in RASTER_DECODE_EXTS:
                    paths.append(os.path.join(base, name))
    else:
        paths = sorted(_page_raster_files(root, pages))
    for path in paths:
        rel = os.path.relpath(path, root)
        try:
            with Image.open(path) as img:
                img.load()                # force a full decode -> catches truncation
                width, height = img.size
        except Exception as exc:           # noqa: BLE001 -- any decode failure is a reject
            failures.append('%s: undecodable/corrupt image (%s: %s)'
                            % (rel, type(exc).__name__, exc))
            continue
        if width <= 0 or height <= 0:
            failures.append('%s: image has a zero dimension (%dx%d)'
                            % (rel, width, height))


def check_card_layout(root, failures):
    # Each page's card sections must grid their cards, not stack them full-width.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        audit = LayoutAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
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


class _ReproToolAudit(html.parser.HTMLParser):
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


class _HeaderNavAudit(html.parser.HTMLParser):
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


class _FooterNavAudit(html.parser.HTMLParser):
    """The ordered (label, href) links of the FIRST <nav class="footer-nav"> that sits INSIDE a
    <footer>. The CSR site carries this nav on every page. Requiring it inside a <footer> means a
    nav moved OUT of the footer no longer satisfies the check (check_footer does not demand a
    footer on subpages, so a bare matching nav elsewhere would otherwise pass). Both the label
    sequence AND the per-link href (resolved against the page's location by check_footer_nav) are
    captured, so a reordered/renamed item OR a retargeted link fails. Parsed, not regex."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._footer = 0
        self._nav = 0
        self._seen = False
        self._in_a = False
        self._label = []
        self._href = ''
        self.links = []

    def handle_starttag(self, tag, attrs):
        amap = dict(attrs)
        classes = (amap.get('class') or '').split()
        if tag == 'footer':
            self._footer += 1
            return
        # Only a footer-nav INSIDE a <footer> counts (the CSR site's footer chrome).
        if tag == 'nav' and 'footer-nav' in classes and self._footer and not self._seen:
            self._seen = True
            self._nav = 1
            return
        if tag == 'nav' and self._nav:
            self._nav += 1
            return
        if self._nav and tag == 'a':
            self._in_a = True
            self._label = []
            self._href = amap.get('href') or ''

    def handle_data(self, data):
        if self._in_a:
            self._label.append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self._in_a:
            self.links.append((''.join(self._label).strip(), self._href))
            self._in_a = False
        elif tag == 'nav' and self._nav:
            self._nav -= 1
        elif tag == 'footer' and self._footer:
            self._footer -= 1

    def result(self):
        return tuple(self.links) if self._seen else None


def _footer_nav(markup):
    audit = _FooterNavAudit()
    audit.feed(markup)
    return audit.result()


def _footer_nav_resolved(links, rel):
    """Map a page's footer (label, href) links to (label, site-root-relative target), resolving
    each depth-relative href against the page's own directory. So the SAME nav rendered at two
    depths (`../about/` vs `about/`) yields the IDENTICAL resolved tuple -- while a link
    RETARGETED to a different page changes it (caught here, since check_links only proves the new
    target exists). An absolute or external href is kept verbatim (nothing to resolve)."""
    out = []
    page_dir = posixpath.dirname(rel)
    for label, href in links:
        target = href
        if href and not _is_external(href) and not href.startswith('/') \
                and not href.startswith('#'):
            target = posixpath.normpath(posixpath.join(page_dir, href))
        out.append((label, target))
    return tuple(out)


def check_footer_nav(root, failures):
    # The CSR site (vendor-neutral, not in FAMILY) carries its OWN consistent footer navigation,
    # emitted from site.toml. Assert PRESENCE on every page (a <nav class="footer-nav"> inside
    # a <footer>) and cross-page CONSISTENCY of (label, RESOLVED-target) -- NOT a hardcoded item
    # set, so the footer_links stay site.toml-driven; a dropped / renamed / reordered item OR a
    # retargeted link fails. Replaces the family-footer-links assertion for the csr policy.
    navs = {}
    missing = []
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        with open(page, encoding='utf-8') as handle:
            links = _footer_nav(handle.read())
        if not links:
            missing.append(rel)
        else:
            navs[rel] = _footer_nav_resolved(links, rel)
    for rel in sorted(missing):
        failures.append('%s: no footer nav (expected a <nav class="footer-nav"> inside a '
                        '<footer>, with links)' % rel)
    if len(set(navs.values())) <= 1:
        return
    counts: dict[tuple, int] = {}
    for nav in navs.values():
        counts[nav] = counts.get(nav, 0) + 1
    canonical = max(counts, key=counts.__getitem__)
    for rel, nav in sorted(navs.items()):
        if nav != canonical:
            failures.append('%s: footer nav inconsistent with the rest of the site '
                            '(label/target %s vs %s)' % (rel, list(nav), list(canonical)))


class _TocAudit(html.parser.HTMLParser):
    """The on-this-page TOC's linked fragment ids (`href="#x"` inside a
    <nav class="toc">) and every top-level `.cat` section id. Parsed, not raw
    regex, so single-quoted attributes are normalized and a `.cat` section (or a
    TOC) sitting inside an HTML comment is invisible -- matching every other audit
    in this file, and unlike the double-quote-only regex it replaces."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._toc = 0
        self.has_toc = False
        self.linked = set()
        self.sections = []        # ids of .cat sections, in document order

    def handle_starttag(self, tag, attrs):
        amap = dict(attrs)
        classes = (amap.get('class') or '').split()
        if tag == 'nav' and 'toc' in classes:
            self._toc += 1
            self.has_toc = True
        elif tag == 'nav' and self._toc:
            self._toc += 1            # a nested <nav> inside the TOC
        if self._toc and tag == 'a':
            href = amap.get('href') or ''
            if href.startswith('#'):
                self.linked.add(href[1:])
        if tag == 'section' and 'cat' in classes and amap.get('id'):
            self.sections.append(amap['id'])

    def handle_endtag(self, tag):
        if tag == 'nav' and self._toc:
            self._toc -= 1


def check_toc_complete(root, failures, pages=None):
    # A page's "On this page" TOC (<nav class="toc">) must list EVERY top-level content
    # section (<section class="cat" id=...>), so a newly added section cannot silently
    # drift out of the page navigation. The zoom-verify screenshots section shipped with a
    # full section but no TOC entry, and nothing caught it -- check_nav only guards the
    # site-wide header nav, and check_links only that a TOC anchor RESOLVES, never that a
    # section is REACHED. Directional: a TOC may also link non-section anchors (rows, sub-
    # headings); only a `.cat` section missing from the TOC is a failure.
    for page in (html_files(root) if pages is None else pages):
        with open(page, encoding='utf-8') as handle:
            audit = _TocAudit()
            audit.feed(handle.read())
        if not audit.has_toc:
            continue                       # a page with no on-this-page TOC is exempt
        rel = os.path.relpath(page, root)
        for sid in audit.sections:
            if sid not in audit.linked:
                failures.append('%s: section #%s is missing from the on-this-page TOC'
                                % (rel, sid))


# --- Forced line breaks in headings -------------------------------------------
# A hard <br> inside a heading forces a wrap point that fights responsive
# reflow: on a narrow phone the heading's first segment already wraps on its own,
# and the <br> then adds ANOTHER line, orphaning a word ("The text on your /
# screen / can lie to you." -- 3 lines, "screen" alone). Headings must wrap
# naturally (CSS text-wrap:balance), never with a hard break. Flagged for h1-h6
# only; a <br> in body prose or a table cell is legitimate and never touched.
_HEADINGS = frozenset({'h1', 'h2', 'h3', 'h4', 'h5', 'h6'})


class _HeadingBreakAudit(html.parser.HTMLParser):
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


def check_heading_breaks(root, failures, pages=None):
    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        audit = _HeadingBreakAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        if audit.hits:
            failures.append(
                '%s: %d hard <br> inside a heading; remove it and let the heading '
                'wrap naturally (CSS text-wrap:balance) so it never orphans a word '
                'on mobile' % (rel, audit.hits))


class _IdAudit(html.parser.HTMLParser):
    """Collect every document-tree element id in order (duplicates kept).

    Two element kinds do not contribute document-tree ids and are handled distinctly, because
    html.parser does NOT model either the way a browser does:
    - <textarea>/<title> are RCDATA: their body is literal TEXT to a browser, not elements. But
      html.parser only auto-treats <script>/<style> as opaque, so without help it would emit
      spurious start/end events for tag-looking text inside them (reporting phantom ids, or a
      stray </textarea> desyncing a depth counter). Extending CDATA_CONTENT_ELEMENTS makes
      html.parser skip their bodies as opaque (close-tag matching still works) -- the correct fix.
    - <template> contents ARE real elements, just a separate DocumentFragment tree (an id there
      may validly repeat a document id). html.parser parses them normally, so a depth counter
      over real template start/end events is accurate; skip ids while inside one."""

    # textarea/title added to the stock ('script', 'style') so their RCDATA bodies are opaque.
    CDATA_CONTENT_ELEMENTS = ('script', 'style', 'textarea', 'title')

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self._template_depth = 0

    def handle_starttag(self, tag, attrs):
        if self._template_depth:
            if tag == 'template':
                self._template_depth += 1
            return
        for name, value in attrs:
            if name == 'id' and value:
                self.ids.append(value)
        if tag == 'template':
            self._template_depth += 1

    def handle_endtag(self, tag):
        if tag == 'template' and self._template_depth:
            self._template_depth -= 1


def check_duplicate_ids(root, failures, pages=None):
    # An id must be unique per document: a duplicate makes `#fragment` targeting
    # ambiguous (the browser scrolls to the FIRST, every other reference silently
    # wrong) and is invalid HTML. A universally-quantified invariant over every page;
    # tidy only WARNs on it (advisory, non-gating), so decide it here.
    for page in (html_files(root) if pages is None else pages):
        rel = os.path.relpath(page, root)
        audit = _IdAudit()
        with open(page, encoding='utf-8') as handle:
            audit.feed(handle.read())
        seen: set[str] = set()
        reported: set[str] = set()      # set membership keeps this O(n), not O(n^2)
        dupes: list[str] = []
        for ident in audit.ids:
            if ident in seen and ident not in reported:
                dupes.append(ident)
                reported.add(ident)
            seen.add(ident)
        if dupes:
            failures.append('%s: duplicate element id(s): %s (a #fragment to a repeated '
                            'id is ambiguous)' % (rel, ', '.join(dupes)))


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
# A bare `color:` text declaration only -- the (?<![\w-]) rejects the tail of
# `background-color:` / `border-color:` / `outline-color:` etc., so a token used
# only as a background or border is not wrongly judged for text contrast.
_COLOR_VAR_USE = re.compile(
    r'(?<![\w-])color\s*:\s*var\(\s*--([\w-]+)\s*\)', re.IGNORECASE)
_HEX = re.compile(r'^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$')
_RGB = re.compile(r'^rgba?\(([^)]*)\)', re.IGNORECASE)
_HSL = re.compile(r'^hsla?\(([^)]*)\)', re.IGNORECASE)


def _channel(token):
    # An rgb() component: a number 0-255 (CSS Color 4 allows a fractional value),
    # or a percentage of 255.
    token = token.strip()
    if token.endswith('%'):
        return min(255, max(0, round(float(token[:-1]) * 255 / 100)))
    return min(255, max(0, round(float(token))))


def _opaque_alpha(token):
    # An rgba()/hsla() alpha component is opaque at 1 (or 100%); anything less is
    # semi-transparent -- its rendered contrast depends on compositing over the
    # page background, which a context-free color parse cannot model.
    token = token.strip()
    value = float(token[:-1]) / 100 if token.endswith('%') else float(token)
    return value >= 1.0


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
    return tuple(min(255, max(0, round(component(offset) * 255)))
                 for offset in (hue + 1 / 3, hue, hue - 1 / 3))


def _parse_color(value):
    """(r, g, b) for a hex, rgb()/rgba() (integer or %), or hsl()/hsla() color;
    else None (a named color, an unresolved var(), ...). var() indirection is
    resolved by the caller (_resolve_color) before this sees the value."""
    value = value.strip()
    match = _HEX.match(value)
    if match:
        digits = match.group(1)
        if len(digits) in (3, 4):                  # #rgb / #rgba shorthand
            digits = ''.join(ch * 2 for ch in digits)
        if len(digits) == 8 and digits[6:8].lower() != 'ff':
            return None            # semi-transparent: contrast needs compositing
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
    match = _RGB.match(value)
    if match:
        parts = [p for p in re.split(r'[\s,/]+', match.group(1).strip()) if p]
        if len(parts) >= 3:
            # OverflowError: an overflowing literal (1e309 -> inf) is unparseable,
            # skipped like any other bad token -- never a crash of the whole gate.
            try:
                if len(parts) >= 4 and not _opaque_alpha(parts[3]):
                    return None    # semi-transparent: contrast needs compositing
                return (_channel(parts[0]), _channel(parts[1]), _channel(parts[2]))
            except (ValueError, OverflowError):
                return None
    match = _HSL.match(value)
    if match:
        parts = [p for p in re.split(r'[\s,/]+', match.group(1).strip()) if p]
        if len(parts) >= 3:
            try:
                if len(parts) >= 4 and not _opaque_alpha(parts[3]):
                    return None    # semi-transparent: contrast needs compositing
                hue = _hue_deg(parts[0])
                sat = float(parts[1].rstrip('%')) / 100
                light = float(parts[2].rstrip('%')) / 100
            except (ValueError, OverflowError):
                return None
            if not (math.isfinite(hue) and math.isfinite(sat)
                    and math.isfinite(light)):
                return None                        # inf/NaN -> unparseable, no crash
            # A browser clamps out-of-range S/L to [0,1] before rendering.
            sat = min(1.0, max(0.0, sat))
            light = min(1.0, max(0.0, light))
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


def _css_sources(root, pages=None):
    """Each independent stylesheet scope of a site, as (label, css-text): every
    .css file (always whole-tree -- a handful of site-wide sheets), plus the
    embedded <style>/style="" bundle of each AUDITED page (every page when
    `pages` is None; a curated subset otherwise). Scopes are kept SEPARATE -- a
    subsite (git-diffs-lie/style.css) carries its own theme with its own --bg and
    --accent, so merging it into the parent's CSS would conflate two different
    color vocabularies (and pick the wrong --accent, last-wins)."""
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
    for page in (html_files(root) if pages is None else pages):
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


def check_contrast(root, failures, pages=None):
    # Per stylesheet scope: parse its :root token palette and, when it defines a
    # page background (--bg), check every paper-text token it both defines and
    # uses as text (color:var(--token)) clears WCAG AA for small text.
    for label, css in _css_sources(root, pages):
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


def _defined_css_classes(root):
    """Every class name defined in any stylesheet scope under `root` -- all .css files plus
    inline <style>/style="" bundles, flattened (comment-stripped by _css_sources)."""
    css = '\n'.join(text for _label, text in _css_sources(root))  # all .css + inline
    return set(re.findall(r'\.(-?[_a-zA-Z][_a-zA-Z0-9-]*)', css))


def check_undefined_classes(root, failures):
    defined = _defined_css_classes(root)
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


def check_generated_class_contract(root, failures):
    # The test-results plane is emitted by test-results-site-generate (dist-ai), whose emitted CSS
    # classes are a generator-owned manifest (dm_test_results.site_classes.GENERATED_CLASSES).
    # style.css is hand-maintained in THIS site repo -- a DIFFERENT repo from the generator -- so
    # nothing coupled the two: the generator's new .stage boot caption shipped with no rule, and
    # undefined-classes (sole-class only) blocked every publish from behind a 25-page failure. This
    # asserts /style.css defines EVERY manifest class -- including the st-<status> CO-classes
    # undefined-classes skips by design -- and names the one missing class, not N pages. No-op
    # where no generated PAGE exists, so it never runs on a site that does not use the generator,
    # nor on a half-built tree that holds only goldens/ (and thus references no manifest class yet).
    # Gate on the overview index.html the generator always writes, not the bare directory.
    if not os.path.isfile(os.path.join(root, RESULTS_SUBDIR, 'index.html')):
        return
    try:
        from dm_test_results import site_classes as results_classes
    except ImportError as exc:
        # Generated tree present but its generator package is not importable -> the contract cannot
        # be verified. FAIL loud; a silent pass here is the false green this gate exists to prevent.
        failures.append(
            '%s present but dm_test_results is not importable (%s): cannot verify the '
            'generated-class contract' % (RESULTS_SUBDIR, exc))
        return
    # Scope to the ONE stylesheet the generated pages load (`<link href="/style.css">` at the site
    # root), not the union of every .css under the tree: a rule in an unlinked sheet or a sibling
    # page's inline <style> would not reach the results pages, so it must not count as "defined".
    # "Defined" is the same dot-token heuristic check_undefined_classes uses (kept identical on
    # purpose); style.css is small and hand-maintained, so a class name buried in a url()/string is
    # not a realistic false match.
    style_path = os.path.join(root, 'style.css')
    try:
        with open(style_path, encoding='utf-8') as handle:
            css = _strip_css_comments(handle.read())
    except OSError as exc:
        failures.append(
            '%s is present but /style.css is unreadable (%s): the generated pages load it and '
            'cannot be style-checked' % (RESULTS_SUBDIR, exc))
        return
    defined = set(re.findall(r'\.(-?[_a-zA-Z][_a-zA-Z0-9-]*)', css))
    for name in sorted(results_classes.GENERATED_CLASSES):
        if name not in defined:
            failures.append(
                'generator-emitted class %r has no CSS rule in /style.css -- '
                'test-results-site-generate emits it; add a rule or the element ships unstyled'
                % name)


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
    keeps its .html name. The ephemeral test-results plane (RESULTS_SUBDIR) is
    excluded -- its per-run pages churn, so listing them would destabilize the
    sitemap. A page is NOT excluded merely for carrying a noindex meta: a
    temporarily-no-index site (every page noindex on an interim host) still
    advertises its real, stable pages, and keeps them out of indexes per-page via
    the meta, not by dropping them from the sitemap. Assumes the site is served at
    the domain root (true for every <owner>.github.io Pages site here)."""
    urls = set()
    for page in html_files(root):
        rel = os.path.relpath(page, root).replace(os.sep, '/')
        if rel == RESULTS_SUBDIR or rel.startswith(RESULTS_SUBDIR + '/'):
            continue
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


def _site_no_index(root):
    """True if the site is a no-index (interim/preview) build: its homepage
    carries a robots noindex meta. The generator stamps that exact meta on every
    page of a no-index build; the homepage is representative."""
    try:
        with open(os.path.join(root, 'index.html'),
                  encoding='utf-8', errors='replace') as handle:
            return 'name="robots" content="noindex"' in handle.read()
    except OSError:
        return False


def render_robots(host, no_index=False):
    """The canonical robots.txt text for a site (trailing newline included).
    Always allows crawling HTML (a crawler must fetch a page to honor its
    per-page noindex meta) and advertises the sitemap. A no-index build ALSO
    Disallows PDFs: a PDF carries no noindex meta and GitHub Pages serves no
    X-Robots-Tag, so a crawl block is the only Pages-compatible lever. It keeps
    PDF CONTENT out of search (uncrawled -> no snippet/indexed text); it does not
    guarantee the bare URL never appears if externally linked (a known robots
    limitation). Users still download it -- robots binds crawlers, not browsers."""
    lines = ['User-agent: *', 'Allow: /']
    if no_index:
        lines.append('Disallow: /*.pdf$')
    return '\n'.join(lines) + '\n\nSitemap: https://%s/sitemap.xml\n' % host


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
    no_index = _site_no_index(root)
    for name, want in (('sitemap.xml', render_sitemap(root, host)),
                       ('robots.txt', render_robots(host, no_index))):
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


# MediaWiki-generated pages (the kicksecure/whonix stage sites) carry MediaWiki's own CSS
# class tokens (mw-editsection, mw-headline, mw-parser-output, ...); the hand-authored family
# pages carry none. A quorum of distinct mw-* class tokens in the landing page POSITIVELY
# identifies a wiki checkout, so main() refuses the FAMILY policy on it with a clear message
# instead of a wall of false failures (missing family footer, wording, card layout). Positive
# detection (not "lacks a family footer") is deliberate: a genuinely BROKEN family site that
# lost its footer is NOT a wiki, so it still runs the family checks and fails loudly rather
# than being silently skipped. The declarative .github/web-tests.yml `policies:` selector
# supersedes this heuristic once each site ships it.
_WIKI_CLASS_TOKEN = re.compile(r'mw-[a-z][a-z0-9-]*')
_WIKI_SIGNATURE_QUORUM = 2


class _WikiClassProbe(html.parser.HTMLParser):
    """Collect distinct mw-* CSS class tokens from REAL element class attributes. Parsing
    (not a raw `class="..."` regex over the markup) is load-bearing: the parser ignores mw-
    tokens that appear only in an HTML comment, in page text, in a <pre>/<code> sample showing
    wiki markup, inside a <script>/<style> body, or in a non-class attribute (data-class=...).
    A raw scan miscounts all of those and would FALSELY mark a real site a wiki -- skipping it
    and letting its CSP / inline-script issues pass CI silently (the skip-as-green trap)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tokens: set[str] = set()

    def handle_starttag(self, tag, attrs):
        cls = dict(attrs).get('class')
        if cls:
            self.tokens.update(t for t in cls.split() if _WIKI_CLASS_TOKEN.fullmatch(t))


def _looks_like_wiki(root):
    index = os.path.join(root, 'index.html')
    try:
        with open(index, encoding='utf-8', errors='replace') as handle:
            markup = handle.read()
    except OSError:
        return False
    probe = _WikiClassProbe()
    probe.feed(markup)
    return len(probe.tokens) >= _WIKI_SIGNATURE_QUORUM


def _policy_for(root):
    """The consistency-suite policy for `root`: 'family' | 'csr' | 'wiki', or None to SKIP.

    The declarative `.github/web-tests.yml` `policies:` is authoritative when present;
    with no config, fall back to the markup heuristic (a MediaWiki tree runs the 'wiki'
    battery). Returns (policy_or_None, reason_when_skipped).

    - 'family': the hand-authored sibling Pages sites -- the full battery incl. the
      FAMILY-footer-links assertion.
    - 'csr': the vendor-neutral academic site (computer-security-research) -- the family
      battery MINUS the FAMILY-footer-links assertion (not in FAMILY), PLUS its own
      footer-nav-consistency + stricter-CSP + perfect-SEO assertions.
    - 'wiki': the MediaWiki-generated static trees (<site>-wiki-static) -- the generic
      HTML-quality + security battery (links, wording, CSP, no-inline-js, a11y, SEO, ...).
      The hand-authored family/CSR chrome checks (family footer links + footer-row classes,
      card layout, review banner, header nav, the family class-vocabulary + generated-class
      contract) do NOT apply: wiki chrome is mw-* classes with a different footer/nav."""
    declared = config.policies(root)
    if declared is not None:
        if 'wiki' in declared:
            return 'wiki', ''
        if 'csr' in declared:
            return 'csr', ''
        if 'family' in declared:
            return 'family', ''
        return None, ('web-tests.yml policies=%s -- no family/csr/wiki policy selected '
                      'for this site' % ','.join(declared))
    if _looks_like_wiki(root):
        return 'wiki', ''
    return 'family', ''


class CuratedPathsError(Exception):
    """The wiki curated-paths file is missing, or a listed path resolves to no file
    on disk -- a STALE list, a fail-loud bug, never a silent skip."""


def _default_curated_paths_file():
    """The curated wiki sample shipped in usr/share/website-tests. site.py lives at
    usr/lib/python3/dist-packages/dist_ai/webcheck/; the data file is five levels up
    at usr/share/website-tests/ -- the same relative layout installed (.deb) or run
    from a checkout, so no env var and nothing to recall."""
    here = os.path.dirname(os.path.realpath(__file__))
    return os.path.normpath(os.path.join(
        here, '..', '..', '..', '..', '..',
        'share', 'website-tests', 'axe-wiki-curated-paths.txt'))


# The SINGLE source of the wiki sample -- the SAME file the axe lane samples
# (axe._load_paths_file), so the two lanes audit the identical representative set.
WIKI_CURATED_PATHS_FILE = _default_curated_paths_file()


def _load_curated_paths(curated_file):
    # Reuse the axe lane's parser (blank / '#' lines skipped) so the file format has
    # one reader, not a second copy that drifts.
    from dist_ai.webcheck import axe
    return axe._load_paths_file(curated_file)


def audited_pages(root, policy, curated_file=None):
    """The HTML pages to AUDIT under `policy`, as absolute file paths.

    family / csr: every navigable page (html_files). wiki: ONLY the curated
    representative sample -- a MediaWiki tree is thousands of pages, too many to
    re-parse on every check, so the gate audits a fixed representative subset. The
    full tree stays on disk, so check_links still resolves every link target against
    it; only the AUDITED set is restricted.

    A curated flat URL maps to disk via _abs_candidates -- the SAME resolver
    check_links uses for a root-absolute link, so the two never drift: /wiki/ISO ->
    wiki/ISO.html, / -> index.html. These ARE page URLs (navigational=True), so the
    clean-URL .html fallback applies here. A curated entry that resolves to no file
    on disk is a STALE list -> CuratedPathsError (fail loud), never a silent skip."""
    if policy != 'wiki':
        return sorted(html_files(root))
    curated_file = curated_file or WIKI_CURATED_PATHS_FILE
    if not os.path.isfile(curated_file):
        raise CuratedPathsError('wiki curated-paths file not found: %s' % curated_file)
    pages = []
    missing = []
    for url in _load_curated_paths(curated_file):
        candidates = _abs_candidates(url.lstrip('/'), [root], navigational=True)
        hit = next((c for c in candidates if os.path.isfile(c)), None)
        if hit is None:
            missing.append(url)
        else:
            pages.append(os.path.normpath(hit))
    if missing:
        raise CuratedPathsError(
            'curated wiki path(s) resolve to no file under %s (stale %s?): %s'
            % (root, curated_file, ', '.join(missing)))
    # An empty / comment-only curated file audits ZERO pages: that is a vacuous
    # pass (exit 0 "all clean" over an unaudited tree), the false green this gate
    # exists to prevent -- fail loud, never return an empty audit set.
    if not pages:
        raise CuratedPathsError(
            'wiki curated-paths file audits zero pages (empty or comment-only): %s'
            % curated_file)
    return pages


def main():
    from dist_ai.webcheck import cli
    argv_roots = sys.argv[1:]
    if not argv_roots:
        # Genuinely nothing requested (the orchestrator passed no root): a legitimate SKIP.
        sys.stderr.write('website-tests: SKIP (no site root given)\n')
        return 77
    # But a NAMED root that does not resolve is a mistyped target -> FAIL loud, never a silent
    # drop that lets a surviving root exit 0 (the silent-green class).
    roots = cli.require_existing_dirs(argv_roots, 'website-tests')
    # Applicability guard: a consistency policy (family | csr) runs only where it is
    # selected -- by the site's `.github/web-tests.yml` `policies:` (authoritative) or,
    # absent that, by the markup heuristic (a wiki tree is skipped). A malformed config
    # FAILS LOUD (never a silent wrong-policy run).
    applicable = []
    config_failures = 0
    for root in roots:
        name = os.path.basename(root)
        try:
            policy, reason = _policy_for(root)
        except config.ConfigError as exc:
            sys.stderr.write('FAIL %s: %s\n' % (name, exc))
            config_failures += 1
            continue
        if policy is not None:
            applicable.append((root, policy))
        else:
            sys.stderr.write('website-tests: SKIP %s (%s)\n' % (name, reason))
    if not applicable:
        if config_failures:
            sys.stderr.write('website-tests: %d failure(s)\n' % config_failures)
            return 1
        sys.stderr.write('website-tests: SKIP (no family/csr-policy site root given)\n')
        return 77
    by_name = {os.path.basename(r): r for r, _policy in applicable}
    total = config_failures
    for root, policy in applicable:
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
        # The pages to AUDIT: every navigable page (family/csr), or the curated
        # representative sample (wiki -- the full tree is too large to re-parse per
        # check; it stays on disk for link-target resolution). A stale curated entry
        # FAILS LOUD, never a silent skip.
        try:
            pages = audited_pages(root, policy)
        except CuratedPathsError as exc:
            sys.stderr.write('FAIL %s: %s\n' % (os.path.basename(root), exc))
            total += 1
            continue
        # Generic HTML-quality + security battery -- runs under EVERY policy
        # (family, csr, wiki), scoped to the audited pages. check_footer's
        # family-links assertion is gated to 'family' (the CSR + wiki trees are not
        # in FAMILY); its footer-EXISTS check still runs for all.
        check_links(root, failures, mount, parent_roots, pages)
        check_wording(root, failures, pages)
        check_footer(root, failures, require_family_links=(policy == 'family'), pages=pages)
        check_csp(root, failures, pages)
        check_no_inline_script(root, failures, pages)
        check_fouc(root, failures, pages)
        check_supply_chain(root, failures, pages)
        check_image_format(root, failures, pages)
        # Orphaned-image detection needs the WHOLE corpus (an image is orphaned only
        # when NO page references it), so it is meaningless on a curated subset and
        # far too slow on a full wiki tree -- family/CSR only.
        if policy != 'wiki':
            check_assets(root, failures)
        # Raster integrity: wiki decodes only the rasters the AUDITED pages reference
        # (the tree holds thousands, irrelevant to a curated audit); family/csr decode
        # the whole tree (small, and an unreferenced-but-corrupt image still fails).
        check_asset_integrity(root, failures, pages if policy == 'wiki' else None)
        check_heading_breaks(root, failures, pages)
        check_duplicate_ids(root, failures, pages)
        check_contrast(root, failures, pages)
        check_toc_complete(root, failures, pages)
        check_seo_current(root, failures)
        # Hand-authored family/CSR chrome -- NOT the MediaWiki-generated wiki trees,
        # whose chrome is mw-* classes with a different footer/nav + its own class
        # vocabulary, so these would misfire wholesale. check_freshness / check_banner
        # inspect only the site-root index.html by design (the "last generated" line +
        # review-status banner are landing-page concerns); check_footer_structure runs
        # on every page so a generated subpage's footer cannot drift unchecked.
        if policy != 'wiki':
            check_freshness(root, failures)
            check_footer_structure(root, failures)
            check_banner(root, failures)
            check_card_layout(root, failures)
            check_repro_raw(root, failures)
            check_nav(root, failures)
            check_undefined_classes(root, failures)
            check_generated_class_contract(root, failures)
        # CSR-only (vendor-neutral, not in FAMILY): its own footer-nav-consistency
        # check, the stricter CSR CSP assertion, and the perfect-SEO page-metadata bar.
        if policy == 'csr':
            check_footer_nav(root, failures)
            check_csr_csp(root, failures)
            check_page_metadata(root, failures)
        name = os.path.basename(root)
        if failures:
            total += len(failures)
            for item in failures:
                sys.stderr.write('FAIL %s: %s\n' % (name, item))
        else:
            sys.stdout.write('ok %s: all %s-policy checks clean\n' % (name, policy))
    sys.stdout.write('website-tests: %d failure(s)\n' % total)
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
