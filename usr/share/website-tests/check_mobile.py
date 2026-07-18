## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Mobile-overflow guard for the GitHub Pages sites: load every page at a narrow
phone viewport and assert nothing makes the page body scroll sideways (a wide
table or code block must scroll inside its own container, never widen the body).

This needs a real browser (Playwright + chromium), so unlike check_site.py it is
NOT pure/static. It SKIPs (exit 77) cleanly when Playwright or the chromium engine
is unavailable, so the static suite still runs everywhere; where a browser IS
present (CI, the sandbox) it gates the layout.

Sites are served over HTTP (not file://) so absolute asset paths resolve and
images load -- a broken image renders at its width attribute and would be a false
overflow. A subsite (git-diffs-lie) is mounted under its parent's docroot at its
real path so its cross-site assets (/style.css, /logo-wide.png, ...) resolve.

Usage: check_mobile.py <site-root> [<site-root> ...]
"""

import os
import sys
import functools
import http.server
import socketserver
import threading

VIEWPORT = 390

# Subsite dir basename -> (parent dir basename, mount path). Mirrors check_site.py.
SUBSITES = {
    'git-diffs-lie': ('output-lies.github.io', '/git-diffs-lie/'),
}


def _skip(msg):
    sys.stderr.write('website-mobile-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


def _page_paths(docroot, subroot):
    """Real URL paths for every navigable page under subroot, relative to docroot
    (so a subsite's pages get their mounted /git-diffs-lie/... path)."""
    paths = []
    for base, _dirs, files in os.walk(subroot):
        if os.sep + '.git' in base:
            continue
        present = set(files)
        for name in files:
            if not name.endswith('.html'):
                continue
            if name[:-5] + '.png' in present:      # image-render template, not a page
                continue
            full = os.path.join(base, name)
            rel = os.path.relpath(full, docroot).replace(os.sep, '/')
            # a .../index.html is served at its directory path
            url = '/' + (rel[:-len('index.html')] if rel.endswith('index.html') else rel)
            paths.append(url)
    return sorted(set(paths))


def _serve(docroot, port):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=docroot)
    httpd = socketserver.TCPServer(('127.0.0.1', port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    roots = [os.path.normpath(r) for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _skip('python3-playwright not installed')

    by_name = {os.path.basename(r): r for r in roots}
    # Build (docroot, [(url, subroot)]) work items. A top-level site serves itself;
    # a subsite is mounted under its parent at its mount path (skipped if the
    # parent is not among the roots -- its assets could not resolve).
    docroots = {}     # docroot -> list of page URLs
    subroot_of = {}   # docroot -> the subroot dir the pages belong to (for logging)
    for root in roots:
        name = os.path.basename(root)
        sub = SUBSITES.get(name)
        if sub:
            parent_name, mount = sub
            parent = by_name.get(parent_name)
            if not parent:
                sys.stdout.write('  ....  %s skipped (parent %s not checked out)\n'
                                 % (name, parent_name))
                continue
            link = os.path.join(parent, mount.strip('/'))
            if not os.path.exists(link):
                try:
                    os.symlink(root, link)
                except OSError:
                    sys.stdout.write('  ....  %s skipped (cannot mount under %s)\n'
                                     % (name, parent_name))
                    continue
            docroots.setdefault(parent, [])
            docroots[parent] += _page_paths(parent, root)
        else:
            docroots.setdefault(root, [])
            docroots[root] += _page_paths(root, root)

    port = 8760
    failures = 0
    checked = 0
    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:            # noqa: BLE001 -- engine not installed
                _skip('chromium engine unavailable: %s' % exc)
            for docroot, urls in docroots.items():
                httpd = _serve(docroot, port)
                try:
                    for url in sorted(set(urls)):
                        page = browser.new_page(viewport={'width': VIEWPORT, 'height': 844})
                        try:
                            page.goto('http://127.0.0.1:%d%s' % (port, url))
                            page.wait_for_timeout(400)
                            sw = page.evaluate('document.documentElement.scrollWidth')
                            iw = page.evaluate('window.innerWidth')
                            checked += 1
                            if sw > iw + 1:
                                off = page.evaluate(
                                    "(vw)=>{let o=[];document.querySelectorAll('*')"
                                    ".forEach(e=>{let r=e.getBoundingClientRect();"
                                    "if(r.right>vw+1)o.push((e.tagName+'.'+(e.getAttribute('class')||''))"
                                    ".slice(0,40)+'~'+Math.round(r.right))});"
                                    "return o.sort((a,b)=>parseInt(b.split('~')[1])-parseInt(a.split('~')[1])).slice(0,4)}",
                                    VIEWPORT)
                                failures += 1
                                sys.stderr.write(
                                    'FAIL %s: horizontal overflow at %dpx '
                                    '(scrollWidth=%d); widest: %s\n'
                                    % (url, VIEWPORT, sw, off))
                        finally:
                            page.close()
                finally:
                    httpd.shutdown()
                port += 1
            browser.close()
    finally:
        # remove any subsite symlinks we created
        for name, (parent_name, mount) in SUBSITES.items():
            parent = by_name.get(parent_name)
            if parent:
                link = os.path.join(parent, mount.strip('/'))
                if os.path.islink(link):
                    os.unlink(link)

    if checked == 0:
        _skip('no pages served (subsite parents absent?)')
    if failures:
        sys.stdout.write('website-mobile-tests: %d overflow failure(s) across %d pages\n'
                         % (failures, checked))
        return 1
    sys.stdout.write('website-mobile-tests: %d pages, no horizontal overflow at %dpx\n'
                     % (checked, VIEWPORT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
