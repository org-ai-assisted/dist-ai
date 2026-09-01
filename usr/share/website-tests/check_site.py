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
import os
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


class Extractor(html.parser.HTMLParser):
    """Collect (attr) link targets, element ids, and the concatenated visible
    text (script/style excluded) of one HTML document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # (tag, attr, value) for href/src
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
        for key in ('href', 'src'):
            if key in amap and amap[key] is not None:
                self.links.append((tag, key, amap[key]))

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


def _abs_candidates(rel, search_roots):
    """Filesystem candidates for a root-absolute path `rel` across search_roots."""
    candidates = []
    for sr in search_roots:
        base = os.path.normpath(os.path.join(sr, rel))
        candidates.append(base)
        if rel == '' or rel.endswith('/') or not os.path.splitext(base)[1]:
            candidates += [os.path.join(base, 'index.html'), base + '.html']
    return candidates


def resolve_internal(root, page, target, mount=None, parent_roots=()):
    """Map an internal href/src to a filesystem path candidate list, or None if
    the link is external / a pure fragment / non-navigational. For a subsite,
    `mount` is its path under the parent domain and `parent_roots` are the parent
    site checkouts its off-mount absolute links resolve against."""
    if target.startswith(('http://', 'https://', 'mailto:', 'tel:', 'data:',
                           'javascript:')):
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
        if mount and (target == mount.rstrip('/') or target.startswith(mount)):
            return ('file', _abs_candidates(target[len(mount):], [root]), frag)
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
    base = os.path.normpath(os.path.join(os.path.dirname(page), target))
    candidates = [base]
    if target.endswith('/') or not os.path.splitext(base)[1]:
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
                failures.append('%s: broken internal link %r -> %s'
                                % (rel, value, candidates[0]))
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
    r'(\d{4})-(\d{2})(?:-(\d{2}))?', re.IGNORECASE)
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


def check_footer(root, failures):
    index = os.path.join(root, 'index.html')
    if not os.path.isfile(index):
        return
    with open(index, encoding='utf-8') as handle:
        markup = handle.read()
    lower = markup.lower()
    if '<footer' not in lower:
        failures.append('index.html: no <footer>')
        return
    footer = lower[lower.index('<footer'):]
    for name, url in FAMILY.items():
        if url not in footer:
            failures.append('index.html: footer missing family link %s' % url)


def check_banner(root, failures):
    index = os.path.join(root, 'index.html')
    if not os.path.isfile(index):
        return
    with open(index, encoding='utf-8') as handle:
        markup = handle.read()
    # A review-status pill, WHERE PRESENT, must say review is needed -- never a
    # "working"/green claim. Not every site carries one, so absence is allowed.
    if 'class="status"' in markup:
        # the pill may be a <span> (static) or an <a> (links to the review-model
        # explanation) -- accept either so a link form is still text-checked.
        pill = re.search(r'<(?:span|a) class="status"[^>]*>([^<]*)</(?:span|a)>', markup)
        if pill and 'review' not in pill.group(1).lower():
            failures.append('index.html: status banner is %r; must indicate '
                            'human review needed' % pill.group(1).strip())


# Elements whose named attribute FETCHES a subresource at load time (unlike an
# <a href> or a <link rel=canonical>, which are navigation/metadata, not loads).
RESOURCE_ATTR = {
    'script': 'src', 'img': 'src', 'iframe': 'src', 'source': 'src',
    'embed': 'src', 'audio': 'src', 'video': 'src', 'track': 'src',
    'object': 'data',
}

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
# srcset may be single- OR double-quoted.
_SRCSET = re.compile(r"""srcset\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)


def _css_urls(text):
    for match in _CSS_URL.finditer(text):
        yield next(group for group in match.groups() if group is not None)


def _srcsets(text):
    for match in _SRCSET.finditer(text):
        yield next(group for group in match.groups() if group is not None)
# Basenames a human has cleared to remain a raster (webp came out no smaller).
# Keep this SMALL and justified; every entry is a content image that stays PNG.
STATIC_IMAGE_ALLOWLIST: frozenset[str] = frozenset()


def _is_raster(url):
    return bool(_RASTER_REF.search(url.split('#', 1)[0].split('?', 1)[0]))


def _allowed_raster(url):
    base = os.path.basename(url.split('#', 1)[0].split('?', 1)[0])
    return base in STATIC_IMAGE_ALLOWLIST


def check_image_format(root, failures):
    # Content raster references must be webp (except the static allowlist). Covers
    # <img>/<source> src, srcset candidates, <a href> to a raster, and CSS url()
    # in a .css file or an inline/embedded style.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        with open(page, encoding='utf-8') as handle:
            markup = handle.read()
        ext = Extractor()
        ext.feed(markup)
        for tag, attr, value in ext.links:
            content = (tag in ('img', 'source') and attr == 'src') or \
                (tag == 'a' and attr == 'href' and _is_raster(value))
            if content and _is_raster(value) and not _allowed_raster(value):
                failures.append('%s: content image %r must be webp (convert with '
                                'site-image-optimize)' % (rel, value))
        for srcset in _srcsets(markup):
            for candidate in srcset.split(','):
                token = candidate.strip().split()
                if token and _is_raster(token[0]) and not _allowed_raster(token[0]):
                    failures.append('%s: srcset image %r must be webp'
                                    % (rel, token[0]))
        for value in _css_urls('\n'.join(ext.styles)):
            if _is_raster(value) and not _allowed_raster(value):
                failures.append('%s: CSS url() image %r must be webp'
                                % (rel, value))
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
        if "default-src 'none'" not in csp:
            failures.append("%s: CSP default-src is not 'none'" % rel)
        if 'http:' in csp or 'https:' in csp or '//' in csp:
            failures.append('%s: CSP allow-lists an external host' % rel)
        directives = _csp_directives(csp)
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


class _InlineJSAudit(html.parser.HTMLParser):
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
                    and value.strip().lower().startswith('javascript:')):
                self.js_url = True

    def handle_startendtag(self, tag, attrs):
        # A self-closing tag (e.g. <input onfocus=..>) has no body, so it never
        # opens an inline <script>; only its attributes matter.
        self._scan_attrs(attrs)

    def handle_starttag(self, tag, attrs):
        self._scan_attrs(attrs)
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
    # Supply chain: no page may fetch a subresource (script, image, media) from
    # an external host or protocol-relative URL -- everything ships self-hosted or
    # inline (data:). External <a> navigation is fine; only loads are flagged.
    for page in html_files(root):
        rel = os.path.relpath(page, root)
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        for tag, attr, value in ext.links:
            if RESOURCE_ATTR.get(tag) != attr:
                continue
            if value.startswith(('http://', 'https://', '//')):
                failures.append('%s: <%s %s> loads an external resource: %s'
                                % (rel, tag, attr, value))


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

    def handle_startendtag(self, tag, attrs):
        # A self-closed wide element (XHTML-style <img/>) still exempts its card.
        if tag in WIDE_TAGS:
            self._mark_wide()

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


def _header_nav(markup):
    """The ordered (label, href) list of the header's <nav> links, or None if the
    page has no header nav. The home-anchor prefix is normalized so an index page's
    `#install` and a sub-page's `/#install` compare equal, and the transient
    class="active" on the current page's own link is ignored -- only the link SET,
    ORDER and targets matter for consistency."""
    low = markup.lower()
    if '<header' not in low:
        return None
    header = markup[low.index('<header'):]
    end = header.lower().find('</header>')
    if end != -1:
        header = header[:end]
    # The header carries one bare <nav>; the footer's is <nav class="fcols">.
    match = re.search(r'<nav>(.*?)</nav>', header, re.DOTALL)
    if not match:
        return None
    links = []
    for anchor in re.finditer(r'<a\b([^>]*)>(.*?)</a>', match.group(1), re.DOTALL):
        label = re.sub(r'<[^>]+>', '', anchor.group(2)).strip()
        href_match = re.search(r'href="([^"]*)"', anchor.group(1))
        href = href_match.group(1) if href_match else ''
        if href.startswith('/#'):          # /#install (sub-page) == #install (index)
            href = href[1:]
        links.append((label, href))
    return tuple(links)


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
        if tag in _HEADINGS:
            self._depth += 1
        elif tag == 'br' and self._depth:
            self.hits += 1

    def handle_startendtag(self, tag, attrs):
        # <br/> self-closing form still counts.
        if tag == 'br' and self._depth:
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
_RGB = re.compile(r'^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)', re.IGNORECASE)


def _parse_color(value):
    """(r, g, b) for a hex or rgb()/rgba() color, else None (var(), named, ...)."""
    value = value.strip()
    match = _HEX.match(value)
    if match:
        digits = match.group(1)
        if len(digits) == 3:
            digits = ''.join(ch * 2 for ch in digits)
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
    match = _RGB.match(value)
    if match:
        return tuple(min(255, int(component)) for component in match.groups())
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
    for base, dirs, files in os.walk(root):
        _prune_git(dirs)
        for name in sorted(files):
            if not name.endswith('.css'):
                continue
            path = os.path.join(base, name)
            try:
                with open(path, encoding='utf-8') as handle:
                    yield os.path.relpath(path, root), handle.read()
            except OSError:
                continue
    for page in html_files(root):
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        if ext.styles:
            yield os.path.relpath(page, root), '\n'.join(ext.styles)


def check_contrast(root, failures):
    # Per stylesheet scope: parse its :root token palette and, when it defines a
    # page background (--bg), check every paper-text token it both defines and
    # uses as text (color:var(--token)) clears WCAG AA for small text.
    for label, css in _css_sources(root):
        props = {}
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
                rgb = _parse_color(value)
                if rgb is not None:
                    props[name] = rgb          # later definition wins (cascade)
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
        check_nav(root, failures)
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
                             'supply-chain + assets + card-layout + nav + '
                             'heading-breaks + contrast + undefined-classes + '
                             'seo clean\n' % name)
    sys.stdout.write('website-tests: %d failure(s)\n' % total)
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
