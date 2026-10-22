#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Rendered-layout guard for the GitHub Pages sites: load every page in a real
browser and assert the things the static suite cannot see because they depend on
layout and the computed cascade:
  - no horizontal body overflow at 320/390/768px (a wide table or code block
    must scroll inside its own container, never widen the body);
  - the sticky header stays a compact single bar at 390px (<= HEADER_MAX_PX),
    not a stack of rows that eats the phone viewport;
  - every rendered text node clears WCAG AA contrast against its effective
    background, in BOTH the light AND the prefers-color-scheme:dark palette
    (catches low contrast from any source, not only :root tokens);
  - no content box spills its own text past its padding edge (per-element
    overflow -- the body-overflow check cannot see an in-box spill);
  - no <img> is broken (404/decode-fail: blank, and not a console error) or
    rendered at a ratio that distorts its intrinsic aspect ratio;
  - the header items do not overlap across a width sweep.

Geometry audits (overflow / element-overflow / broken-image / aspect) run on EVERY engine
in WEBCHECK_BROWSERS (default `chromium`; the sandbox adds firefox/webkit where
provisioned), because layout is where the engines diverge. The color + header +
text-resize audits are engine-independent and run on the primary (chromium) only.

This needs a real browser (Playwright), so unlike check_site.py it is NOT
pure/static. It SKIPs (exit 77) cleanly when Playwright or every requested engine
is unavailable, so the static suite still runs everywhere; where a browser IS
present (CI, the sandbox) it gates the layout. A requested engine that fails to
launch while another engine runs is a loud failure, not a silent skip.

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
from typing import Any, NoReturn

VIEWPORT = 390                       # primary phone width (used in messages/checks)
# Body must never scroll sideways from a narrow phone up to a small tablet.
OVERFLOW_WIDTHS = (320, 390, 768)
# A mobile sticky header must stay a compact single bar, not a stack of rows.
HEADER_MAX_PX = 100
# Widths swept for header-overlap: phone through the mobile<->desktop handoff,
# where a toggle label, a status pill and the brand crowd each other. The header
# is uniform across a site's pages, so this sweeps the index once per site.
HEADER_SWEEP_WIDTHS = (340, 360, 414, 560, 680, 768, 900, 1100)
# Minimum gap (px) required between the toggle's icon and its label text.
_ICON_TEXT_MIN_GAP = 3

# Subsite dir basename -> (parent dir basename, mount path). Mirrors check_site.py.
SUBSITES: dict[str, tuple[str, str]] = {
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

# Header overlap audit (swept across widths): catches the menu-toggle label
# running into its own hamburger icon, and any two header items (brand, status,
# toggle, nav) whose boxes overlap. Args: (minGap) for the icon<->label spacing.
_HEADER_OVERLAP_JS = r"""
(minGap) => {
  const out = [];
  const hdr = document.querySelector('header');
  if (!hdr) return out;
  const shown = (el) => {
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  // 1) the menu toggle's label text must not sit on top of its icon (::before)
  const btn = hdr.querySelector('.menubtn, summary');
  if (btn && shown(btn)) {
    const cs = getComputedStyle(btn);
    if (parseFloat(cs.fontSize) > 0) {                 // a text label is rendered
      const bf = getComputedStyle(btn, '::before');
      const iconW = parseFloat(bf.width) || 0;
      if (iconW > 0) {
        const r = btn.getBoundingClientRect();
        const iconVisualRight = r.left + (parseFloat(cs.paddingLeft) || 0) + iconW;
        const w = document.createTreeWalker(btn, NodeFilter.SHOW_TEXT);
        let node, textLeft = null;
        while ((node = w.nextNode())) {
          if (node.textContent.trim()) {
            const rng = document.createRange();
            rng.selectNodeContents(node);
            textLeft = rng.getBoundingClientRect().left;
            break;
          }
        }
        if (textLeft !== null && textLeft - iconVisualRight < minGap) {
          out.push('menu toggle label overlaps its icon (gap ' +
            Math.round(textLeft - iconVisualRight) + 'px < ' + minGap + 'px)');
        }
      }
    }
  }
  // 2) header items must not overlap each other (closed state: nav is a normal
  // inline row on desktop / hidden on mobile, so this compares what is visible)
  const name = (el) => el.tagName.toLowerCase() +
    (el.className ? '.' + String(el.className).split(' ')[0] : '');
  const kids = [...hdr.querySelectorAll('.brand, .status, .menubtn, summary, nav')]
    .filter(shown);
  for (let i = 0; i < kids.length; i++) {
    for (let j = i + 1; j < kids.length; j++) {
      if (kids[i].contains(kids[j]) || kids[j].contains(kids[i])) continue;
      const a = kids[i].getBoundingClientRect(), b = kids[j].getBoundingClientRect();
      const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left);
      const oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (ox > 2 && oy > 2) {
        out.push('header items overlap: ' + name(kids[i]) + ' & ' + name(kids[j]) +
          ' (' + Math.round(ox) + 'x' + Math.round(oy) + 'px)');
      }
    }
  }
  return out;
}
"""


# Browser engines to render under. chromium is the default and the PRIMARY
# (color/DOM-math audits run on it ONLY, engine-independent); geometry audits
# (overflow, overlap, truncation, aspect) run on EVERY listed engine, because
# layout is where WebKit/Gecko diverge from Blink. WEBCHECK_BROWSERS is a
# space/comma list; the sandbox driver sets it to the engines it provisioned.
def _browsers_from_env() -> list[str]:
    raw = os.environ.get('WEBCHECK_BROWSERS', 'chromium')
    names = [n for n in raw.replace(',', ' ').split() if n]
    # chromium stays the primary: keep it first, dedup preserving order.
    ordered, seen = [], set()
    for n in (['chromium'] + names if 'chromium' in names else names):
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered or ['chromium']


# Contrast must hold in BOTH color schemes: the sites ship a
# @media (prefers-color-scheme: dark) palette that the light-only render never
# exercises. The color math is engine-independent, so this runs on the primary
# engine only, once per scheme.
COLOR_SCHEMES = ('light', 'dark')

# Per-ELEMENT content overflow: a content box laid out wider than its padding
# box (scrollWidth > clientWidth) -- text spilling past the box's right edge even
# when the PAGE itself does not scroll (the body-overflow check cannot see this).
# Ported from mw-static-generator/tools/check-mobile-overflow.py's _ELEMENT_OVERFLOW_JS
# (validated 0 false-positives on a live sweep); this module is the CANONICAL home
# so the two consumers cannot drift -- the wiki tool should import it from here.
# SCOPE is the family-site content boxes (the wiki tool passes its own classes);
# the FP-avoidance is engine-general, not scope-specific:
#   - only overflow-x:visible (the default) spills OUT; hidden/clip/auto/scroll
#     are not a visible spill, so measuring scrollWidth there is a false positive;
#   - a by-design scroll surface (pre/table/code viewport) is exempt;
#   - an overflow caused ONLY by an out-of-flow (absolute/fixed) descendant is not
#     a spill and is ignored.
# NOT flagged: the generic body-wide element-OVERLAP heuristic -- an inline element
# wrapped across lines has a bounding box spanning both lines, so two adjacent
# wrapped links read as "overlapping" to box math though they do not. That class
# is high-false-positive (AI-reviewer ranked) and deliberately omitted; the sound
# header-overlap sweep (flex/block items, no inline wrap) stays.
_ELEMENT_OVERFLOW_SCOPE = (".issue, .pcard, .inst, .ibody, .lead, .kv, .catdesc, .toc, "
                           ".info-box, .mbox")
_ELEMENT_OVERFLOW_EXEMPT = "pre, table, .term, .copybox, .code-select, .viewport"
_ELEMENT_OVERFLOW_JS = r"""
(cfg) => {
  var SCOPE = cfg.scope, EXEMPT_ANCESTOR = cfg.exempt;
  var hits = [], seen = new Set();
  Array.prototype.forEach.call(document.querySelectorAll(SCOPE), function (el) {
    if (seen.has(el)) return;
    var cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return;
    if (el.getClientRects().length === 0) return;
    if (cs.overflowX !== 'visible') return;
    if (el.closest(EXEMPT_ANCESTOR)) return;
    var over = el.scrollWidth - el.clientWidth;
    if (over <= 1) return;
    var pb = el.getBoundingClientRect();
    var inflow = Array.prototype.some.call(el.querySelectorAll('*'), function (c) {
      var ccs = getComputedStyle(c);
      if (ccs.position === 'absolute' || ccs.position === 'fixed') return false;
      return c.getBoundingClientRect().right > pb.right - parseFloat(cs.paddingRight || 0)
             - parseFloat(cs.borderRightWidth || 0) + 1;
    });
    if (!inflow) return;
    seen.add(el);
    var s = el.tagName.toLowerCase();
    var cls = (el.getAttribute('class') || '').trim();
    if (cls) { s += '.' + cls.split(/\s+/).slice(0, 3).join('.'); }
    hits.push(s + ' overflows ' + Math.round(over) + 'px: ' +
      JSON.stringify((el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 45)));
  });
  return hits.slice(0, 8);
}
"""

# Broken / zero-dimension images: an <img> that 404'd or failed to decode renders
# blank. A FAILED image subresource is NOT a JS console error or CSP violation, so
# the console gate misses it -- a real gap. Ported from the same wiki tool;
# `complete && naturalWidth===0` is the reliable broken signal. No loading=lazy
# position skip: `complete` is ALREADY false for any not-yet-loaded (incl. lazy,
# incl. display:none-never-fetched) image, so a position skip only mis-skipped
# BROKEN lazy images the browser HAD loaded past ~1.5 viewports -- a false pass,
# and these sites' result galleries are lazy (dev1238, grok ai-review, 61d6c25).
_BROKEN_IMG_JS = r"""
() => {
  var out = [];
  Array.prototype.forEach.call(document.querySelectorAll('img'), function (img) {
    if (img.complete && img.naturalWidth === 0) {
      out.push(((img.currentSrc || img.getAttribute('src') || '(inline)').slice(-60)) +
        (img.alt ? ' alt=' + JSON.stringify(img.alt.slice(0, 30)) : ''));
    }
  });
  return out.slice(0, 12);
}
"""

# Image aspect-ratio audit: a rendered <img> whose box ratio diverges from the
# file's intrinsic ratio is stretched/squashed. Tolerance is generous (5%) so a
# sub-pixel rounding never trips it; tiny icons and not-yet-loaded images are
# skipped (natural dims 0).
_ASPECT_TOLERANCE = 0.05
_ASPECT_JS = r"""
(tol) => {
  const out = [];
  for (const img of document.querySelectorAll('img')) {
    const nw = img.naturalWidth, nh = img.naturalHeight;
    const r = img.getBoundingClientRect();
    if (!nw || !nh || r.width < 2 || r.height < 2) continue;
    const natural = nw / nh, rendered = r.width / r.height;
    if (Math.abs(rendered - natural) / natural > tol) {
      out.push((img.getAttribute('src') || '(inline)').slice(0, 50) +
        ' natural ' + nw + 'x' + nh + ' -> rendered ' +
        Math.round(r.width) + 'x' + Math.round(r.height));
    }
  }
  return out.slice(0, 6);
}
"""

def _skip(msg: str) -> NoReturn:
    sys.stderr.write('website-mobile-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


class _MountingTCPServer(socketserver.TCPServer):
    """TCPServer that carries the two attributes _MountHandler / main() stash
    on the instance (bare-declared: no class-level value, so this is a type
    declaration only -- plain socketserver.TCPServer does not declare them)."""

    mounts: dict[str, str]
    daemon_threads: bool


class _MountHandler(http.server.SimpleHTTPRequestHandler):
    """Serve `directory` at /, plus each entry of the server's `mounts`
    (mount-path -> subsite-root) at its mount path -- so a subsite is served under
    its parent's docroot with no filesystem changes."""

    def log_message(self, *_args):
        pass                                     # quiet

    def translate_path(self, path):
        clean = urllib.parse.unquote(urllib.parse.urlsplit(path).path)
        mounts = getattr(self.server, 'mounts', {})
        fs = None
        for mount, subroot in mounts.items():
            if clean == mount.rstrip('/') or clean.startswith(mount):
                fs = os.path.normpath(os.path.join(subroot, clean[len(mount):].lstrip('/')))
                break
        if fs is None:
            fs = super().translate_path(path)
        # Containment via REALPATH: an in-tree symlink whose TARGET escapes every served root
        # (e.g. leak.txt -> /etc/passwd) must be refused, not served to the network-capable
        # browser -- a real exfil surface. normpath above only resolves '..' lexically, not
        # symlink targets, so the check is on the real path against the docroot + each subroot.
        allowed = [os.path.realpath(self.directory)]
        allowed += [os.path.realpath(s) for s in mounts.values()]
        real = os.path.realpath(fs)
        if not any(real == a or real.startswith(a + os.sep) for a in allowed):
            return os.path.join(self.directory, '__forbidden__')
        if os.path.isdir(real):
            return os.path.join(real, 'index.html')
        return real


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
    docroots: dict[str, dict[str, Any]] = {}     # docroot -> {'mounts': {mount: subroot}, 'urls': [..]}
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

    browsers = _browsers_from_env()
    primary = browsers[0]
    failures = 0
    checked = 0
    with sync_playwright() as pw:
        # Launch every requested engine. An engine that will not launch is a
        # whole-lane SKIP (77) ONLY when NO engine launched (no browser at all);
        # a requested engine that fails while another already runs is a
        # provisioning bug for an EXPLICIT request -> a loud failure, never a
        # silent green (mirrors the runner's explicit-but-invalid rule).
        engines: list[tuple[str, Any]] = []
        for name in browsers:
            launcher = getattr(pw, name, None)
            if launcher is None:
                if not engines and name == browsers[-1]:
                    _skip('unknown browser engine(s): %s' % ' '.join(browsers))
                sys.stderr.write('FAIL: requested browser engine %r unknown\n' % name)
                failures += 1
                continue
            try:
                engines.append((name, launcher.launch()))
            except Exception as exc:            # noqa: BLE001 -- engine not installed
                if not engines and name == browsers[-1]:
                    _skip('no browser engine available (%s): %s' % (' '.join(browsers), exc))
                sys.stderr.write('FAIL: requested browser engine %r unavailable: %s\n'
                                 % (name, exc))
                failures += 1
        for docroot, entry in docroots.items():
            handler = functools.partial(_MountHandler, directory=docroot)
            httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
            httpd.mounts = entry['mounts']
            port = httpd.server_address[1]
            httpd.daemon_threads = True
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                for engine_name, browser in engines:
                    is_primary = engine_name == primary
                    tag = '' if is_primary else ' [%s]' % engine_name
                    for url in sorted(set(entry['urls'])):
                        if is_primary:
                            checked += 1
                        base = 'http://127.0.0.1:%d%s' % (port, url)
                        for width in OVERFLOW_WIDTHS:
                            page = browser.new_page(viewport={'width': width, 'height': 844})
                            try:
                                resp = page.goto(base)
                                if resp is not None and resp.status >= 400:
                                    failures += 1
                                    sys.stderr.write('FAIL %s%s: served %d (not a real page)\n'
                                                     % (url, tag, resp.status))
                                    break
                                page.wait_for_timeout(400)
                                sw = page.evaluate('document.documentElement.scrollWidth')
                                iw = page.evaluate('window.innerWidth')
                                if sw > iw + 1:
                                    off = page.evaluate(_OVERFLOW_JS, width)
                                    failures += 1
                                    sys.stderr.write(
                                        'FAIL %s%s: horizontal overflow at %dpx '
                                        '(scrollWidth=%d); widest: %s\n'
                                        % (url, tag, width, sw, off))
                                if width != VIEWPORT:
                                    continue
                                # VIEWPORT-width audits. Geometry (element-overflow
                                # / broken-image / aspect) runs on EVERY engine;
                                # color + header + text-resize on the primary only.
                                eo_cfg = {'scope': _ELEMENT_OVERFLOW_SCOPE,
                                          'exempt': _ELEMENT_OVERFLOW_EXEMPT}
                                for msg in page.evaluate(_ELEMENT_OVERFLOW_JS, eo_cfg):
                                    failures += 1
                                    sys.stderr.write('FAIL %s%s: element overflow: %s\n'
                                                     % (url, tag, msg))
                                for msg in page.evaluate(_BROKEN_IMG_JS):
                                    failures += 1
                                    sys.stderr.write('FAIL %s%s: broken image: %s\n'
                                                     % (url, tag, msg))
                                for msg in page.evaluate(_ASPECT_JS, _ASPECT_TOLERANCE):
                                    failures += 1
                                    sys.stderr.write('FAIL %s%s: image aspect-ratio distorted: %s\n'
                                                     % (url, tag, msg))
                                if not is_primary:
                                    continue
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
                                        '<%s class=%r> %r (light)\n'
                                        % (url, item['cr'], item['need'],
                                           item['tag'].lower(), item['cls'], item['text']))
                            finally:
                                page.close()
                        # Dark-scheme contrast: the prefers-color-scheme palette
                        # the light render never exercises. Primary engine only.
                        if is_primary:
                            dpage = browser.new_page(viewport={'width': VIEWPORT, 'height': 844},
                                                     color_scheme='dark')
                            try:
                                resp = dpage.goto(base)
                                if resp is None or resp.status < 400:
                                    dpage.wait_for_timeout(400)
                                    for item in dpage.evaluate(_CONTRAST_JS):
                                        failures += 1
                                        sys.stderr.write(
                                            'FAIL %s: text contrast %s:1 (need %s:1) '
                                            '<%s class=%r> %r (dark)\n'
                                            % (url, item['cr'], item['need'],
                                               item['tag'].lower(), item['cls'], item['text']))
                            finally:
                                dpage.close()
                    # Header-overlap sweep (per engine): the header is uniform
                    # across a site's pages, so check the index across a range of
                    # widths where the brand / status / toggle crowd each other.
                    for width in HEADER_SWEEP_WIDTHS:
                        page = browser.new_page(viewport={'width': width, 'height': 800})
                        try:
                            resp = page.goto('http://127.0.0.1:%d/' % port)
                            if resp is not None and resp.status >= 400:
                                continue
                            page.wait_for_timeout(150)
                            for msg in page.evaluate(_HEADER_OVERLAP_JS, _ICON_TEXT_MIN_GAP):
                                failures += 1
                                sys.stderr.write('FAIL /%s header at %dpx: %s\n'
                                                 % (tag, width, msg))
                        finally:
                            page.close()
            finally:
                httpd.shutdown()
                httpd.server_close()
        for _name, browser in engines:
            browser.close()

    if checked == 0:
        _skip('no pages served (subsite parents absent?)')
    if failures:
        sys.stdout.write('website-mobile-tests: %d failure(s) across %d pages\n'
                         % (failures, checked))
        return 1
    sys.stdout.write('website-mobile-tests: %d pages clean on [%s] -- no overflow at %s px, '
                     'header <=%dpx, WCAG-AA text contrast (%s), no element spill, '
                     'no broken images, image aspect ratios kept, no header overlap %s px\n'
                     % (checked, ' '.join(browsers),
                        '/'.join(str(w) for w in OVERFLOW_WIDTHS), HEADER_MAX_PX,
                        '+'.join(COLOR_SCHEMES),
                        '/'.join(str(w) for w in HEADER_SWEEP_WIDTHS)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
