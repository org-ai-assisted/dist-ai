#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static checks for the project's GitHub Pages sites (output-lies.github.io,
secure-terminal.github.io, org-ai-assisted.github.io). Catches the bug classes
that shipped before: broken internal links, missing footer "family" links,
lowercase "open source"/"free software" in prose, and a wrong review-status
banner. Pure standard library, no network.

Usage: check_site.py <site-root> [<site-root> ...]
Exit 0 if all checks pass, 1 on any failure, 77 (SKIP) if no root resolves.

Each <site-root> is the directory holding a site's index.html. The site's own
identity is inferred from its directory name (matched against the known family).
"""

import html.parser
import os
import re
import sys

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
KNOWN_PROJECT_PATHS = (
    '/git-diffs-lie/',
)

# Sub-sites served UNDER another family site's domain (a project-Pages repo): the
# subsite's directory basename -> (parent site directory basename, mount path
# under the parent domain). A subsite's root-absolute links resolve against its
# OWN tree when they fall under the mount, and against the PARENT site's tree
# otherwise (a link like /terminal/ from git-diffs-lie points at the output-lies
# site). Both must be checked out to verify the cross-site links; when the parent
# is absent those links are treated as external (unverifiable), never failed.
SUBSITES = {
    'git-diffs-lie': ('output-lies.github.io', '/git-diffs-lie/'),
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
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
        amap = dict(attrs)
        if amap.get('id'):
            self.ids.add(amap['id'])
        if amap.get('name') and tag == 'a':
            self.ids.add(amap['name'])
        if tag == 'meta' and (amap.get('http-equiv') or '').lower() \
                == 'content-security-policy':
            self.csp = amap.get('content') or ''
        for key in ('href', 'src'):
            if key in amap and amap[key] is not None:
                self.links.append((tag, key, amap[key]))

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.text_parts.append(data)

    def text(self):
        return ''.join(self.text_parts)


def html_files(root):
    for base, _dirs, files in os.walk(root):
        if os.sep + '.git' in base:
            continue
        present = set(files)
        for name in files:
            if not name.endswith('.html'):
                continue
            # Skip image-generation templates (logo.html -> logo.png, og.html ->
            # og.png, ...): a .html with a same-basename .png sibling is a render
            # source for an image, not a navigable page.
            if name[:-5] + '.png' in present:
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


_IDS_CACHE = {}


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
        pill = re.search(r'<span class="status"[^>]*>([^<]*)</span>', markup)
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


def check_csp(root, failures):
    # Every page must carry a strict CSP: default-src 'none' and no external host
    # allow-listed (the site's baseline is self + unsafe-inline + data: only).
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
        nav = _header_nav(open(page, encoding='utf-8').read())
        if nav is not None:
            navs[os.path.relpath(page, root)] = nav
    if len(set(navs.values())) <= 1:
        return
    counts = {}
    for nav in navs.values():
        counts[nav] = counts.get(nav, 0) + 1
    canonical = max(counts, key=counts.get)      # the most common nav = the baseline
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


def main():
    roots = [os.path.normpath(r) for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        sys.stderr.write('website-tests: SKIP (no site root found)\n')
        return 77
    by_name = {os.path.basename(r): r for r in roots}
    total = 0
    for root in roots:
        failures = []
        # A subsite (git-diffs-lie) verifies its off-mount absolute links against
        # its parent site's checkout when that is also present.
        mount = None
        parent_roots = ()
        sub = SUBSITES.get(os.path.basename(root))
        if sub:
            parent_name, mount = sub
            if parent_name in by_name:
                parent_roots = (by_name[parent_name],)
        check_links(root, failures, mount, parent_roots)
        check_wording(root, failures)
        check_footer(root, failures)
        check_banner(root, failures)
        check_csp(root, failures)
        check_supply_chain(root, failures)
        check_card_layout(root, failures)
        check_nav(root, failures)
        name = os.path.basename(root)
        if failures:
            total += len(failures)
            for item in failures:
                sys.stderr.write('FAIL %s: %s\n' % (name, item))
        else:
            sys.stdout.write('ok %s: links + wording + footer + banner + csp + '
                             'supply-chain + card-layout + nav clean\n' % name)
    sys.stdout.write('website-tests: %d failure(s)\n' % total)
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
