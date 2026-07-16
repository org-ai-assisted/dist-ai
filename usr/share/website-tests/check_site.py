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
        self.links = []          # (kind, value) for href/src
        self.ids = set()
        self.text_parts = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
        amap = dict(attrs)
        if amap.get('id'):
            self.ids.add(amap['id'])
        if amap.get('name') and tag == 'a':
            self.ids.add(amap['name'])
        for key in ('href', 'src'):
            if key in amap and amap[key] is not None:
                self.links.append((key, amap[key]))

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
        for name in files:
            if name.endswith('.html'):
                yield os.path.join(base, name)


def resolve_internal(root, page, target):
    """Map an internal href/src to a filesystem path candidate list, or None if
    the link is external / a pure fragment / non-navigational."""
    if target.startswith(('http://', 'https://', 'mailto:', 'tel:', 'data:',
                           'javascript:')):
        return None
    if any(target.startswith(prefix) for prefix in KNOWN_PROJECT_PATHS):
        return None                          # valid sibling project-Pages path
    frag = ''
    if '#' in target:
        target, frag = target.split('#', 1)
    if target == '':
        return ('#self', frag)               # same-page fragment
    if target.startswith('/'):
        base = os.path.join(root, target.lstrip('/'))
    else:
        base = os.path.join(os.path.dirname(page), target)
    base = os.path.normpath(base)
    candidates = [base]
    if target.endswith('/') or not os.path.splitext(base)[1]:
        candidates += [os.path.join(base, 'index.html'), base + '.html']
    return ('file', candidates, frag)


def check_links(root, failures):
    # Preload ids per page for fragment checks.
    pages = {}
    for page in html_files(root):
        ext = Extractor()
        with open(page, encoding='utf-8') as handle:
            ext.feed(handle.read())
        pages[os.path.normpath(page)] = ext
    for page, ext in pages.items():
        rel = os.path.relpath(page, root)
        for _kind, value in ext.links:
            resolved = resolve_internal(root, page, value)
            if resolved is None:
                continue
            if resolved[0] == '#self':
                frag = resolved[1]
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
            if frag and hit in pages and frag not in pages[hit].ids:
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


def main():
    roots = [r for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        sys.stderr.write('website-tests: SKIP (no site root found)\n')
        return 77
    total = 0
    for root in roots:
        root = os.path.normpath(root)
        failures = []
        check_links(root, failures)
        check_wording(root, failures)
        check_footer(root, failures)
        check_banner(root, failures)
        name = os.path.basename(root)
        if failures:
            total += len(failures)
            for item in failures:
                sys.stderr.write('FAIL %s: %s\n' % (name, item))
        else:
            sys.stdout.write('ok %s: links + wording + footer + banner clean\n'
                             % name)
    sys.stdout.write('website-tests: %d failure(s)\n' % total)
    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
