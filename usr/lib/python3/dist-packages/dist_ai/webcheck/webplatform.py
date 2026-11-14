#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Progressive-enhancement web-platform features shared by every family/CSR page:
the Speculation Rules prefetch block and cross-document View Transitions.

Two layers:

  - Pure, browser-FREE validators (canonical bytes, JSON shape, CSS shape, CDP-event
    classification). site.py imports these for its static per-page gate, and the unit
    regression (check_webplatform_test.py) canary-reds each one. No playwright import at
    module load, so importing this module stays browser-free (site.py's fast static path
    imports it).

  - A FUNCTIONAL browser lane (check_roots / check / main), modelled on console.py: serve
    each local checkout from a localhost mount (reusing mobile.py's harness) and, in real
    chromium over CDP, PROVE the features actually work -- the inline speculationrules block
    is ACCEPTED (not CSP-blocked), its moderate-eagerness rule PREFETCHES a same-origin link,
    and the @view-transition rule is PARSED into the CSSOM and a same-origin nav runs clean.
    SKIPs (exit 77) when Playwright/chromium is absent, so the launcher delegates it to the
    sandbox exactly like the sibling browser lanes.

The canonical bytes are the SAME ones mw-static-generator emits on the wikis
(mwstatic/page.py SPECULATION_RULES_JSON + the style.css @view-transition block); the two
generators are independent, so this module is the single source of truth for what the
family + CSR sites must emit, and the static gate pins it byte-for-byte.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys


# ----------------------------------------------------------------------------- #
# Canonical bytes (byte-identical to mw-static-generator/mwstatic/page.py).
# ----------------------------------------------------------------------------- #

# Speculation Rules: declarative same-origin prefetch (Chromium). moderate eagerness =
# hover/pointerdown trigger (bandwidth-friendly, auto-disabled under Data/Battery Saver).
# href_matches "/*" is root-relative => SAME-ORIGIN ONLY (no cross-origin egress). The
# `not selector_matches [data-no-instant]` clause is the ONE opt-out both this and
# instant.page honour, so a heavy same-origin download link (a PDF, a full-size image) marked
# [data-no-instant] is never prefetched. The block is inline, so under a <meta>-delivered CSP
# Chromium demands its sha256 in script-src (the `inline-speculation-rules` keyword is NOT
# honoured for a statically-parsed inline block under meta CSP -- verified empirically); a
# static host cannot mint per-response nonces, and the hash also pins these exact bytes.
SPECULATION_RULES_JSON = (
    '{"prefetch":[{"where":{"and":[{"href_matches":"/*"},'
    '{"not":{"selector_matches":"[data-no-instant]"}}]},"eagerness":"moderate"}]}'
)


def _sha256_b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode('ascii')


# The CSP script-src hash-source that must appear in every page carrying the inline block.
# SPEC_RULES_HASH is the bare source (matches mw-static-generator's naming); SPEC_RULES_CSP_SOURCE
# is the quoted token as it appears in a script-src list -- use it when emitting/comparing a CSP so
# the single quotes are never dropped or doubled.
SPEC_RULES_HASH = 'sha256-' + _sha256_b64(SPECULATION_RULES_JSON)
SPEC_RULES_CSP_SOURCE = "'%s'" % SPEC_RULES_HASH

# The exact inline element the sites emit (what a browser hashes is the text BETWEEN the
# tags, i.e. SPECULATION_RULES_JSON; the wrapper is for authoring convenience only).
SPECULATION_RULES_SCRIPT = (
    '<script type="speculationrules">%s</script>' % SPECULATION_RULES_JSON)

# Cross-document View Transitions: a smooth cross-fade between same-origin page loads. Pure
# CSS (no JS, no CSP change); unsupported browsers (Firefox/Tor Browser) just do an instant
# navigation. Opted in ONLY inside the motion-welcome block, so reduced-motion users (and the
# reduced default) get the instant swap.
VIEW_TRANSITION_CSS = (
    '@media (prefers-reduced-motion: no-preference) {\n'
    '  @view-transition { navigation: auto; }\n'
    '}'
)


# ----------------------------------------------------------------------------- #
# Browser-free validators (unit-tested + canaried).
# ----------------------------------------------------------------------------- #

# An inline <script type="speculationrules">BODY</script>. type is matched
# case-insensitively with optional surrounding whitespace (a browser trims+folds the
# attribute); a src= form is a SEPARATE external ruleset, not this inline block, so it is not
# matched here. DOTALL so a multi-line body is captured whole.
_SPEC_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']?\s*speculationrules\s*["\']?[^>]*>(.*?)</script\s*>',
    re.IGNORECASE | re.DOTALL)


def speculation_block_bodies(html_text: str) -> list[str]:
    """Every inline speculationrules script body in the document, in order. A src= (external)
    ruleset carries no inline body and is not returned (it would need its own validation)."""
    bodies = []
    for match in _SPEC_SCRIPT_RE.finditer(html_text):
        # Skip an external ruleset: <script type=speculationrules src=...> has an (ignored)
        # body a browser never reads. Re-check the opening tag for a src attribute.
        opening = html_text[match.start():match.start(1)]
        if re.search(r'\bsrc\s*=', opening, re.IGNORECASE):
            continue
        bodies.append(match.group(1))
    return bodies


def speculation_json_ok(body: str) -> tuple[bool, str]:
    """(ok, reason) for one inline speculationrules body. Pins the SAME rules/effect across
    every site: byte-exact to SPECULATION_RULES_JSON after whitespace is stripped (a browser
    parses the JSON, so insignificant surrounding whitespace is allowed, but the rule shape is
    fixed). A semantic re-check backs the byte compare so the failure message is specific."""
    stripped = body.strip()
    if not stripped:
        return False, 'empty speculationrules body'
    try:
        data = json.loads(stripped)
    except ValueError as exc:
        return False, 'invalid JSON (%s)' % exc
    # Byte-exact (modulo surrounding whitespace) is the primary, strongest assertion: it keeps
    # the rule identical to the wiki + every sibling site.
    if stripped == SPECULATION_RULES_JSON:
        return True, ''
    # A parseable-but-different block: say exactly which invariant it breaks, so a drift is
    # diagnosable rather than a bare "not byte-identical".
    prefetch = data.get('prefetch') if isinstance(data, dict) else None
    if not isinstance(prefetch, list) or not prefetch:
        return False, 'missing non-empty "prefetch" rule list'
    rule = prefetch[0]
    if not isinstance(rule, dict):
        return False, 'prefetch rule is not an object'
    if rule.get('eagerness') != 'moderate':
        return False, 'eagerness is not "moderate" (got %r)' % rule.get('eagerness')
    where = rule.get('where', {})
    conj = where.get('and') if isinstance(where, dict) else None
    clauses = conj if isinstance(conj, list) else []
    if {'href_matches': '/*'} not in clauses:
        return False, 'missing same-origin href_matches "/*" clause'
    if {'not': {'selector_matches': '[data-no-instant]'}} not in clauses:
        return False, 'missing [data-no-instant] download-exclusion clause'
    # Shape is right but the bytes differ (key order / spacing): the sha256 would not match the
    # pinned SPEC_RULES_HASH, so still reject -- the hash in CSP is over the EXACT bytes.
    return False, 'speculationrules body not byte-identical to the canonical rule'


# Remove CSS comments so a rule commented OUT does not count as present.
_CSS_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
# The motion-welcome media block header, whitespace-robust (a browser folds inner whitespace;
# `no-preference` is the value we require -- NOT `reduce`).
_VT_MEDIA_RE = re.compile(
    r'@media[^{]*\(\s*prefers-reduced-motion\s*:\s*no-preference\s*\)[^{]*\{', re.IGNORECASE)
# @view-transition { ... navigation: auto ... }, whitespace-robust.
_VT_RULE_RE = re.compile(
    r'@view-transition\s*\{[^}]*\bnavigation\s*:\s*auto\b[^}]*\}', re.IGNORECASE)


def view_transition_css_ok(css_text: str) -> bool:
    """True iff the CSS opts into cross-document View Transitions the canonical way: an
    `@view-transition { navigation: auto }` rule nested INSIDE a `prefers-reduced-motion:
    no-preference` media block -- so reduced-motion users get the instant swap. A top-level
    @view-transition outside that guard, or inside a `reduce` block, does NOT satisfy it."""
    text = _CSS_COMMENT_RE.sub(' ', css_text)
    media = _VT_MEDIA_RE.search(text)
    if not media:
        return False
    # Scan from the media block's opening brace to its matching close, and require the VT rule
    # within. Brace-match so a rule after the block (still prefers-reduced-motion:no-preference
    # scoped? no -- after the block it is unguarded) does not count.
    body = _brace_block(text, media.end() - 1)
    return bool(body is not None and _VT_RULE_RE.search(body))


def _brace_block(text: str, open_brace_idx: int) -> str | None:
    """The substring between the brace at `open_brace_idx` and its matching close, or None if
    unbalanced. Nesting-aware so an inner `@view-transition { ... }` does not end the block."""
    depth = 0
    for i in range(open_brace_idx, len(text)):
        ch = text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return text[open_brace_idx + 1:i]
    return None


# ----------------------------------------------------------------------------- #
# CDP-event classification (pure; the functional lane feeds it live events, the unit test
# canaries it with fixtures).
# ----------------------------------------------------------------------------- #

# prefetchStatusUpdated.status values that prove the moderate rule FIRED and the prefetch
# reached (at least) the in-flight state. PrefetchResponseUsed is reported in `prefetchStatus`
# only after the prefetched document is actually navigated to.
PREFETCH_LIVE_STATUSES = frozenset({'Running', 'Ready', 'Success'})


def ruleset_accepted(events: list[dict]) -> tuple[bool, str]:
    """(ok, reason) over collected Preload.ruleSetUpdated event payloads. Accepted iff OUR
    ruleset (its sourceText is the canonical JSON) appears with NO errorType/errorMessage. A
    CSP-blocked inline ruleset is the canary: Chromium reports it here with an errorType (or
    never emits it at all), so a wrong/absent script-src hash fails THIS assertion."""
    ours = []
    for ev in events:
        rule_set = ev.get('ruleSet', ev)
        source = (rule_set.get('sourceText') or '').strip()
        if source == SPECULATION_RULES_JSON:
            ours.append(rule_set)
    if not ours:
        return False, ('no Preload.ruleSetUpdated for the canonical ruleset '
                       '(inline block CSP-blocked, or script-src hash missing/wrong)')
    for rule_set in ours:
        if rule_set.get('errorType') or rule_set.get('errorMessage'):
            return False, ('ruleset rejected: %s %s'
                           % (rule_set.get('errorType'), rule_set.get('errorMessage')))
    return True, ''


def prefetch_fired(events: list[dict]) -> tuple[bool, str]:
    """(ok, reason) over collected Preload.prefetchStatusUpdated payloads: the moderate rule
    actually started a prefetch (status reached Running/Ready/Success for a candidate link)."""
    seen = sorted({ev.get('status') for ev in events if ev.get('status')})
    if any(ev.get('status') in PREFETCH_LIVE_STATUSES for ev in events):
        return True, ''
    if not events:
        return False, 'no Preload.prefetchStatusUpdated events (moderate rule never fired)'
    return False, 'prefetch never reached a live status (saw %s)' % (seen or '[]')


# ----------------------------------------------------------------------------- #
# Functional browser lane.
# ----------------------------------------------------------------------------- #

NAV_TIMEOUT_MS = 30000
# Give the ruleset time to register and the prefetch to start after the pointer trigger.
SETTLE_MS = 1500


def _skip(msg: str):
    # Mirror the sibling browser lanes' SKIP contract: exit 77 so the launcher delegates to the
    # sandbox instead of treating an absent browser as a pass or a hard fail.
    sys.stderr.write('website-webplatform-tests: SKIP (%s)\n' % msg)
    raise SystemExit(77)


# The in-page probe: TAG every same-origin navigable link the moderate rule would match
# (origin === location.origin, pathname !== current, NOT [data-no-instant]) with a sequential
# data-wp-probe marker, and return their count. Mirrors the rule's own where-clause so the link
# we trigger is one the rule matches. Tagging + hovering by selector (vs raw coordinates) is
# robust to sticky headers / overlap / layout differences between sites.
_TAG_CANDIDATES_JS = r"""
() => {
  const here = new URL(location.href);
  let n = 0;
  for (const a of document.querySelectorAll('a[href]')) {
    if (n >= 6) break;
    if (a.matches('[data-no-instant]')) continue;
    if (a.hasAttribute('data-wp-probe')) continue;
    let u;
    try { u = new URL(a.href); } catch (e) { continue; }
    if (u.origin !== here.origin) continue;
    if (u.pathname === here.pathname) continue;
    const r = a.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) continue;   // not rendered (display:none etc.)
    a.setAttribute('data-wp-probe', String(n));
    n++;
  }
  return n;
}
"""

# Is the @view-transition rule PARSED into the live CSSOM? A CSSViewTransitionRule object
# (top-level or nested in the enabled @media block) means the browser accepted and applied it.
_VT_CSSOM_JS = r"""
() => {
  const isVT = (r) => r && r.constructor && r.constructor.name === 'CSSViewTransitionRule';
  for (const sheet of document.styleSheets) {
    let rules;
    try { rules = sheet.cssRules; } catch (e) { continue; }
    for (const rule of rules) {
      if (isVT(rule)) return true;
      let inner;
      try { inner = rule.cssRules; } catch (e) { inner = null; }
      if (inner) { for (const ir of inner) { if (isVT(ir)) return true; } }
    }
  }
  return false;
}
"""


async def _probe_page(browser, base: str, path: str) -> dict:
    """Drive one page through the full functional check in real chromium over CDP."""
    from playwright.async_api import Error as PwError  # noqa: F401  (engine present here)

    context = await browser.new_context()
    page = await context.new_page()
    ruleset_events: list[dict] = []
    prefetch_events: list[dict] = []
    cdp = await context.new_cdp_session(page)
    cdp.on('Preload.ruleSetUpdated', lambda params: ruleset_events.append(params))
    cdp.on('Preload.prefetchStatusUpdated', lambda params: prefetch_events.append(params))
    await cdp.send('Preload.enable')
    try:
        url = base + path
        resp = await page.goto(url, wait_until='domcontentloaded', timeout=NAV_TIMEOUT_MS)
        status = resp.status if resp else 0
        if status < 200 or status >= 400:
            return {'path': path, 'bad_status': status}
        # Let the ruleset register.
        await page.wait_for_timeout(500)
        # Trigger the moderate rule by HOVERING a candidate link (moderate eagerness fires on a
        # ~200ms pointer hover). Deliberately NOT a click/pointerdown-release: completing the
        # click would navigate and destroy this execution context before the VT CSSOM read
        # below. Hover EACH tagged candidate until a prefetch fires -- a single link may sit
        # under a sticky header or be otherwise un-hoverable on a given layout. A page with NO
        # in-scope link is not a FEATURE failure (prefetch assertion skipped then); ruleset
        # accepted + VT still stand.
        n_cand = await page.evaluate(_TAG_CANDIDATES_JS)
        first_href = None
        for i in range(n_cand):
            sel = '[data-wp-probe="%d"]' % i
            if first_href is None:
                try:
                    # The resolved .href DOM property (absolute URL), not the raw relative
                    # attribute -- page.goto needs an absolute URL.
                    first_href = await page.eval_on_selector(sel, 'el => el.href')
                except Exception:  # noqa: BLE001 -- best-effort; keep scanning
                    pass
            try:
                await page.hover(sel, timeout=5000)
            except Exception:  # noqa: BLE001 -- element not hoverable; try the next
                continue
            await page.wait_for_timeout(SETTLE_MS)
            if any(ev.get('status') in PREFETCH_LIVE_STATUSES for ev in prefetch_events):
                break
        vt_applied = await page.evaluate(_VT_CSSOM_JS)
        # A same-origin navigation must run clean with @view-transition navigation:auto set up
        # (Chromium starts a cross-document transition; we assert it does not error).
        nav_ok = True
        nav_detail = ''
        if first_href:
            try:
                nresp = await page.goto(first_href, wait_until='domcontentloaded',
                                        timeout=NAV_TIMEOUT_MS)
                nav_ok = bool(nresp and 200 <= nresp.status < 400)
                if not nav_ok:
                    nav_detail = 'HTTP %s' % (nresp.status if nresp else 'none')
            except Exception as exc:  # noqa: BLE001 -- a nav error is a reportable VT failure
                nav_ok = False
                nav_detail = str(exc)[:200]
        return {
            'path': path,
            'ruleset_events': list(ruleset_events),
            'prefetch_events': list(prefetch_events),
            'had_candidate': n_cand > 0,
            'vt_applied': bool(vt_applied),
            'nav_ok': nav_ok,
            'nav_detail': nav_detail,
        }
    finally:
        try:
            await context.close()
        except Exception:  # noqa: BLE001 -- best-effort teardown
            pass


async def check(base: str, paths: list[str]) -> int:
    from playwright.async_api import async_playwright

    overall = 0
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch()
        except Exception as exc:  # noqa: BLE001 -- engine not installed
            _skip('chromium engine unavailable: %s' % exc)
        try:
            for path in paths:
                res = await _probe_page(browser, base, path)
                label = path or '/'
                if 'bad_status' in res:
                    print('FAIL %-28s served HTTP %d (not a real page)'
                          % (label, res['bad_status']), flush=True)
                    overall = 1
                    continue
                page_fail = []
                ok, reason = ruleset_accepted(res['ruleset_events'])
                if not ok:
                    page_fail.append('speculation ruleset: ' + reason)
                if res['had_candidate']:
                    ok, reason = prefetch_fired(res['prefetch_events'])
                    if not ok:
                        page_fail.append('speculation prefetch: ' + reason)
                if not res['vt_applied']:
                    page_fail.append('view-transition: @view-transition rule not applied in '
                                     'the live CSSOM (parse/support failure)')
                if not res['nav_ok']:
                    page_fail.append('view-transition: same-origin nav errored (%s)'
                                     % res['nav_detail'])
                if page_fail:
                    overall = 1
                    for item in page_fail:
                        print('FAIL %-28s %s' % (label, item), flush=True)
                else:
                    cand_note = '' if res['had_candidate'] else ' (no in-scope link; prefetch n/a)'
                    print('ok   %-28s speculation accepted + prefetching, '
                          'view-transition applied%s' % (label, cand_note), flush=True)
        finally:
            try:
                await browser.close()
            except Exception:  # noqa: BLE001 -- best-effort teardown
                pass
    return overall


def check_roots(roots: list[str]) -> int:
    """FAMILY/CSR entry: serve each local checkout from a localhost mount (reusing mobile.py's
    harness incl. SUBSITES mounting) and run the functional feature gate against its root page.
    SKIPs (exit 77) when Playwright/chromium is absent, like the sibling browser lanes."""
    import os
    import asyncio
    import functools
    import threading

    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401  (engine launch is inside check())
    except ImportError:
        _skip('python3-playwright not installed')

    from dist_ai.webcheck.mobile import (
        _MountHandler, _MountingTCPServer, _page_urls, SUBSITES)

    by_name = {os.path.basename(r): r for r in roots}
    # Group into docroots exactly like console.check_roots / mobile.main(): a subsite is mounted
    # under its parent's docroot at its mount path (skipped if the parent is not checked out).
    docroots: dict[str, dict] = {}
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

    overall = 0
    for docroot, entry in docroots.items():
        handler = functools.partial(_MountHandler, directory=docroot)
        httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
        httpd.mounts = entry['mounts']
        port = httpd.server_address[1]
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            base = 'http://127.0.0.1:%d' % port
            # One representative page per mount: the inline block + stylesheet are byte-identical
            # across a site's pages (static per-page checks cover presence on ALL of them), so the
            # functional CDP proof needs one real page per origin, not every page. The mount root
            # ("/" or the subsite mount path) always carries the block.
            mount_roots = [''] + sorted(entry['mounts'])
            paths = []
            for mnt in mount_roots:
                p = (mnt.rstrip('/') + '/') if mnt else '/'
                if p not in paths:
                    paths.append(p)
            if asyncio.run(check(base, paths)) != 0:
                overall = 1
        finally:
            httpd.shutdown()
    return overall


def main() -> int:
    return check_roots(sys.argv[1:])


if __name__ == '__main__':
    sys.exit(main())
