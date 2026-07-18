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
overflow. A subsite (git-diffs-lie) is served UNDER its parent's docroot at its
real mount path (/git-diffs-lie/) by a path-mapping HTTP handler, so its
cross-site assets (/style.css, /logo-wide.png, ...) resolve WITHOUT touching the
filesystem (no symlinks into the real checkout).

Usage: check_mobile.py <site-root> [<site-root> ...]
"""

import os
import sys
import functools
import http.server
import socketserver
import threading
import urllib.parse

VIEWPORT = 390

# Subsite dir basename -> (parent dir basename, mount path). Mirrors check_site.py.
SUBSITES = {
    'git-diffs-lie': ('output-lies.github.io', '/git-diffs-lie/'),
}


def _skip(msg):
    sys.stderr.write('website-mobile-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


class _MountHandler(http.server.SimpleHTTPRequestHandler):
    """Serve `directory` at /, plus each entry of the server's `mounts`
    (mount-path -> subsite-root) at its mount path -- so a subsite is served under
    its parent's docroot with no filesystem changes."""

    def log_message(self, *_args):
        pass                                     # quiet

    def translate_path(self, path):
        clean = urllib.parse.unquote(urllib.parse.urlsplit(path).path)
        for mount, subroot in getattr(self.server, 'mounts', {}).items():
            if clean == mount.rstrip('/') or clean.startswith(mount):
                rel = clean[len(mount):].lstrip('/')
                fs = os.path.normpath(os.path.join(subroot, rel))
                # keep the resolved path inside the subsite root
                if os.path.commonpath([fs, subroot]) != subroot:
                    return os.path.join(subroot, '__forbidden__')
                if os.path.isdir(fs):
                    fs = os.path.join(fs, 'index.html')
                return fs
        return super().translate_path(path)


def _page_urls(root, mount=''):
    """The URL paths of every navigable page under `root`, prefixed by `mount`
    (the subsite's mount path, or '' for a top-level site)."""
    urls = []
    for base, _dirs, files in os.walk(root):
        if os.sep + '.git' in base:
            continue
        present = set(files)
        for name in files:
            if not name.endswith('.html'):
                continue
            if name[:-5] + '.png' in present:      # image-render template, not a page
                continue
            rel = os.path.relpath(os.path.join(base, name), root).replace(os.sep, '/')
            if rel.endswith('index.html'):
                rel = rel[:-len('index.html')]
            url = mount.rstrip('/') + '/' + rel.lstrip('/')
            urls.append(url if url.startswith('/') else '/' + url)
    return sorted(set(urls))


def main():
    roots = [os.path.abspath(r) for r in sys.argv[1:] if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _skip('python3-playwright not installed')

    by_name = {os.path.basename(r): r for r in roots}
    # Group into docroots: each top-level site serves itself; a subsite is mounted
    # under its parent's docroot at its mount path (skipped if the parent is not
    # checked out -- its cross-site assets could not resolve).
    docroots = {}     # docroot -> {'mounts': {mount: subroot}, 'urls': [..]}
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
            entry = docroots.setdefault(parent, {'mounts': {}, 'urls': []})
            entry['mounts'][mount] = root
            entry['urls'] += _page_urls(root, mount)
        else:
            entry = docroots.setdefault(root, {'mounts': {}, 'urls': []})
            entry['urls'] += _page_urls(root, '')

    failures = 0
    checked = 0
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:                # noqa: BLE001 -- engine not installed
            _skip('chromium engine unavailable: %s' % exc)
        for docroot, entry in docroots.items():
            handler = functools.partial(_MountHandler, directory=docroot)
            httpd = socketserver.TCPServer(('127.0.0.1', 0), handler)
            httpd.mounts = entry['mounts']
            port = httpd.server_address[1]
            httpd.daemon_threads = True
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                for url in sorted(set(entry['urls'])):
                    page = browser.new_page(viewport={'width': VIEWPORT, 'height': 844})
                    try:
                        resp = page.goto('http://127.0.0.1:%d%s' % (port, url))
                        if resp is not None and resp.status >= 400:
                            failures += 1
                            sys.stderr.write('FAIL %s: served %d (not a real page)\n'
                                             % (url, resp.status))
                            continue
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
                httpd.server_close()
        browser.close()

    if checked == 0:
        _skip('no pages served (subsite parents absent?)')
    if failures:
        sys.stdout.write('website-mobile-tests: %d failure(s) across %d pages\n'
                         % (failures, checked))
        return 1
    sys.stdout.write('website-mobile-tests: %d pages, no horizontal overflow at %dpx\n'
                     % (checked, VIEWPORT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
