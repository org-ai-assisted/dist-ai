#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Rendered-layout guard for the GitHub Pages sites: load every page in a real
browser at phone/tablet widths and assert three things the static suite cannot
see because they depend on layout and the computed cascade:
  - no horizontal body overflow at 320/390/768px (a wide table or code block
    must scroll inside its own container, never widen the body);
  - the sticky header stays a compact single bar at 390px (<= HEADER_MAX_PX),
    not a stack of rows that eats the phone viewport;
  - every rendered text node clears WCAG AA contrast against its effective
    background (catches low contrast from any source, not only :root tokens).

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

VIEWPORT = 390                       # primary phone width (used in messages/checks)
# Body must never scroll sideways from a narrow phone up to a small tablet.
OVERFLOW_WIDTHS = (320, 390, 768)
# A mobile sticky header must stay a compact single bar, not a stack of rows.
HEADER_MAX_PX = 100

# Subsite dir basename -> (parent dir basename, mount path). Mirrors check_site.py.
SUBSITES = {
}

# Widest overflowing elements, for a readable failure message.
_OVERFLOW_JS = (
    "(vw)=>{let o=[];document.querySelectorAll('*')"
    ".forEach(e=>{let r=e.getBoundingClientRect();"
    "if(r.right>vw+1)o.push((e.tagName+'.'+(e.getAttribute('class')||''))"
    ".slice(0,40)+'~'+Math.round(r.right))});"
    "return o.sort((a,b)=>parseInt(b.split('~')[1])-parseInt(a.split('~')[1])).slice(0,4)}"
)

# Height the sticky <header> occupies at the top of the viewport (null if none).
_HEADER_JS = (
    "()=>{const h=document.querySelector('header');"
    "return h?h.getBoundingClientRect().height:null}"
)

# Computed-style contrast audit: walk EVERY rendered text node and compare its
# actual foreground color against its effective (first opaque ancestor)
# background, flagging anything below WCAG AA (4.5:1 small, 3:1 large). Unlike
# check_site.py's token check this reads the RENDERED cascade, so it catches low
# contrast from ANY source -- inherited color, an inline style, a hardcoded hex
# -- not only :root tokens (the unknown-unknown catcher). Text over a gradient
# or image background (unknown luminance) and translucent text are skipped
# rather than guessed. Dedups by tag+class+ratio; caps the report.
_CONTRAST_JS = r"""
() => {
  const parse = (c) => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map(x => parseFloat(x));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v/12.92 : Math.pow((v+0.055)/1.055, 2.4); };
  const lum = (c) => 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b);
  const ratio = (a, b) => { const L1 = lum(a)+0.05, L2 = lum(b)+0.05; return L1 > L2 ? L1/L2 : L2/L1; };
  const bgOf = (el) => {
    let n = el;
    while (n && n.nodeType === 1) {
      const s = getComputedStyle(n);
      if (s.backgroundImage && s.backgroundImage !== 'none') return null;
      const bg = parse(s.backgroundColor);
      if (bg && bg.a === 1) return bg;
      n = n.parentElement;
    }
    return { r: 255, g: 255, b: 255 };
  };
  const out = [], seen = new Set();
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = w.nextNode())) {
    const txt = node.textContent.trim();
    if (!txt) continue;
    const el = node.parentElement;
    if (!el) continue;
    // Exempt themed code-sample rendering: a terminal/diff mockup (.term), a
    // command box (.copybox) or any <pre> is a stylized code surface (like an
    // editor color theme), not readable page chrome -- holding its dim comment
    // and prompt colors to AA would churn a deliberate palette and fight the
    // demo. Page chrome (headings, kickers, body, links) stays checked.
    if (el.closest('pre, .term, .copybox')) continue;
    const s = getComputedStyle(el);
    if (s.visibility === 'hidden' || s.display === 'none' || parseFloat(s.opacity) === 0) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) continue;
    const fg = parse(s.color);
    if (!fg || fg.a < 0.95) continue;
    const bg = bgOf(el);
    if (!bg) continue;
    const px = parseFloat(s.fontSize);
    const bold = (parseInt(s.fontWeight) || 400) >= 700;
    const large = px >= 24 || (px >= 18.66 && bold);
    const need = large ? 3.0 : 4.5;
    const cr = ratio(fg, bg);
    if (cr < need - 0.05) {
      const key = el.tagName + '|' + (el.className || '') + '|' + Math.round(cr*100);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ tag: el.tagName, cls: String(el.className || '').slice(0, 30),
                 text: txt.slice(0, 30), cr: Math.round(cr*100)/100, need: need });
    }
  }
  return out.slice(0, 12);
}
"""


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
    for base, dirs, files in os.walk(root):
        # Skip the git metadata dir by EXACT name (not a '/.git' substring test,
        # which also matches '.github'); prune in place so os.walk skips it.
        if '.git' in dirs:
            dirs.remove('.git')
        present = set(files)
        for name in files:
            if not name.endswith('.html'):
                continue
            # Skip an image-render template (logo.html -> logo.webp, og.html ->
            # og.png, ...): a .html with a same-basename image sibling renders an
            # image, it is not a navigable page. Mirror check_site.py.html_files
            # exactly -- checking only .png here let logo-wide.html (a wide logo
            # canvas with a .webp sibling) be page-checked and falsely overflow.
            stem = name[:-5]
            if any(stem + ext in present
                   for ext in ('.png', '.webp', '.jpg', '.jpeg', '.gif')):
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
                    checked += 1
                    base = 'http://127.0.0.1:%d%s' % (port, url)
                    for width in OVERFLOW_WIDTHS:
                        page = browser.new_page(viewport={'width': width, 'height': 844})
                        try:
                            resp = page.goto(base)
                            if resp is not None and resp.status >= 400:
                                failures += 1
                                sys.stderr.write('FAIL %s: served %d (not a real page)\n'
                                                 % (url, resp.status))
                                break
                            page.wait_for_timeout(400)
                            sw = page.evaluate('document.documentElement.scrollWidth')
                            iw = page.evaluate('window.innerWidth')
                            if sw > iw + 1:
                                off = page.evaluate(_OVERFLOW_JS, width)
                                failures += 1
                                sys.stderr.write(
                                    'FAIL %s: horizontal overflow at %dpx '
                                    '(scrollWidth=%d); widest: %s\n'
                                    % (url, width, sw, off))
                            # Header budget + contrast: once, at the phone width.
                            if width == VIEWPORT:
                                hh = page.evaluate(_HEADER_JS)
                                if hh is not None and hh > HEADER_MAX_PX:
                                    failures += 1
                                    sys.stderr.write(
                                        'FAIL %s: sticky header %dpx tall at %dpx '
                                        '(budget %dpx); collapse it\n'
                                        % (url, round(hh), VIEWPORT, HEADER_MAX_PX))
                                for item in page.evaluate(_CONTRAST_JS):
                                    failures += 1
                                    sys.stderr.write(
                                        'FAIL %s: text contrast %s:1 (need %s:1) '
                                        '<%s class=%r> %r\n'
                                        % (url, item['cr'], item['need'],
                                           item['tag'].lower(), item['cls'], item['text']))
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
    sys.stdout.write('website-mobile-tests: %d pages clean -- no overflow at %s px, '
                     'header <=%dpx, WCAG-AA text contrast\n'
                     % (checked, '/'.join(str(w) for w in OVERFLOW_WIDTHS), HEADER_MAX_PX))
    return 0


if __name__ == '__main__':
    sys.exit(main())
