## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""axe-core accessibility REGRESSION gate: baseline store + comparison, plus the local-serve
orchestration.

Generic webcheck lane, shared by the family Pages sites and the wiki stage sites. The static
sites carry pre-existing accessibility debt (a missing landmark, a low-contrast swatch in a demo,
a decorative image with no alt) that is not worth blocking every publish on -- yet a NEW
regression (a heading level skipped, a form control that lost its label, a link that lost its
text) must fail. So the gate is REGRESSION-relative, exactly like the console/lighthouse lanes: a
committed per-site baseline of ACCEPTED violations, and a fresh run FAILS only when a violation
appears that the baseline does not already accept. A baselined violation is tolerated; a resolved
one (in the baseline but no longer firing) is reported, not required.

The engine below (normalize/key/parse/format/compare) is browser-free and unit-tested
(check_axe_test.py); the orchestration serves each site checkout from a localhost mount (reusing
mobile.py's harness, incl. SUBSITES mounting), loads every page in headless chromium, injects
axe-core, and runs it (needs Playwright + chromium + axe-core -> the sandbox, both of which the
sibling lanes also require).

Violation identity: axe reports each violation as a rule id plus a list of NODES, each with a
`target` (the CSS-selector path to the element, an array that grows extra entries across
frame/shadow boundaries). One (path, rule-id, target) key is minted per node, so the same rule
firing on two different elements -- or the same element on two pages -- are distinct keys. This is
what makes the baseline precise: fixing one element's violation does not silently re-accept the
same rule firing elsewhere.

Baseline line format, one key per line:

    <path> <rule-id> <target>

`<path>` (a URL path) and `<rule-id>` (an axe rule id, e.g. color-contrast) never contain
whitespace; the target (a CSS selector, which may) is the remainder of the line. parse_baseline
is the inverse of format_baseline.

axe-core itself is injected from axe.min.js, located via AXE_SOURCE (the driver sets it) or a
couple of well-known npm global paths. Its absence is an env-unmet SKIP(77), like a missing
chromium engine.
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from dist_ai.webcheck.mobile import (
    _MountHandler, _MountingTCPServer, _page_urls, _skip, SUBSITES)

# (page path, axe rule id, normalized target selector).
Key = Tuple[str, str, str]


class _EngineUnavailable(Exception):
    """chromium failed to launch. The CALLER decides SKIP vs FAIL: an env-unmet
    SKIP(77) is only honest when NOTHING has been audited yet. Once a docroot has
    run, a launch failure is a mid-run fault (overall=1), never a silent SKIP."""

_CTRL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def _safe_terminal(s: str) -> str:
    """Strip C0/C1 control chars from captured page text before printing it to the operator's
    terminal. A violation's target/selector is page-derived; even for our own sites, no raw
    control byte (OSC-52, ANSI) reaches the terminal -- mirrors webcheck.console."""
    return _CTRL_CHARS.sub('?', s)


def normalize_target(target) -> str:
    """Reduce axe's node `target` to one stable, comparable selector string.

    axe gives an ARRAY of selectors: a single entry for an element in the top document, extra
    entries when the path crosses a frame/shadow boundary (`['#frame', 'button']`), and a nested
    array for a shadow-DOM hop. Join boundary hops with ' >> ' and any nested selector list with a
    space, so two runs of the same element always produce the identical key. A bare string (older
    axe shapes) and anything unexpected degrade to str() rather than raise -- a malformed target
    must not crash the gate."""
    if isinstance(target, str):
        return target
    if isinstance(target, (list, tuple)):
        parts: List[str] = []
        for element in target:
            if isinstance(element, (list, tuple)):
                parts.append(" ".join(str(x) for x in element))
            else:
                parts.append(str(element))
        return " >> ".join(parts)
    return str(target)


def _canon_path(path: str) -> str:
    """Canonical page identity for a Key, so the two URL spellings of one page collapse to ONE
    form: a curated audit requests /wiki/ISO, a full audit keys /wiki/ISO.html (from _page_urls),
    and committed .html baselines all compare. INDEX-FIRST (mirrors _page_urls' index.html ->
    '/dir/' strip) so a root index.html lands on '/', keeping the leading slash; then the non-index
    .html spelling collapses to extensionless. Idempotent: the output never ends '.html' or
    '/index.html', so re-applying is a no-op."""
    if path.endswith('/index.html'):
        return path[:-len('index.html')]
    if path == 'index.html':
        return '/'
    if path.endswith('.html'):
        return path[:-len('.html')]
    return path


def result_keys(path: str, violations) -> List[Key]:
    """Every (path, rule-id, target) key a page's axe violations produce -- one per node. Pure
    (no browser), so the violation -> key mapping is unit-tested directly. A clean page (no
    violations) yields none. A violation with no nodes still contributes nothing (no element to
    key); that is accurate, not a miss -- a ruleless/nodeless entry names no element to regress
    against."""
    keys: List[Key] = []
    for violation in violations or []:
        rule = str(violation.get("id", "?"))
        for node in violation.get("nodes", []):
            target = normalize_target(node.get("target", []))
            keys.append((_canon_path(path), rule, target))
    return keys


def parse_baseline(text: str) -> Set[Key]:
    """Load a committed baseline into a key set. A blank / `#` line is skipped. A line without at
    least a path and a rule id is a hard error (a malformed line must never read as 'no accepted
    violations', which would fail-closed the whole site into MISSING-like noise or, worse, drop a
    real acceptance)."""
    out: Set[Key] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            raise ValueError("expected '<path> <rule-id> <target>', got: %r" % line)
        path, rule = parts[0], parts[1]
        target = parts[2] if len(parts) == 3 else ""
        out.add((_canon_path(path), rule, target))
    return out


def format_baseline(keys: Set[Key], site: Optional[str] = None) -> str:
    """Render a baseline file: a header, then one sorted line per accepted key. Deterministic sort
    so a re-seed diff is reviewable. parse_baseline(format_baseline(x)) == x."""
    who = (" for %s" % site) if site else ""
    header = [
        "# axe-core accepted-violation baseline%s. Fields: <path> <rule-id> <target>" % who,
        "# The gate FAILS only on a NEW violation (one not listed here). A listed violation is",
        "# pre-existing accessibility debt we tolerate; a listed one that no longer fires is",
        "# reported as resolved, not required. Re-seed (overwrites) with:",
        "#   webcheck-axe-sandbox --write-baseline <site-root>",
    ]
    body = [
        "%s %s %s" % (path, rule, target)
        for (path, rule, target) in sorted(keys)
    ]
    return "\n".join(header + body) + "\n"


def evaluate(baseline_present: bool, baseline: Set[Key],
             fresh: Set[Key]) -> Tuple[int, List[Key], List[Key]]:
    """Compare a fresh violation set against the accepted baseline. Pure, so the whole decision is
    unit-tested without a browser.

    Returns (rc, new, resolved):
      - `new`      = fresh keys the baseline does not accept -> the gate FAILS on any.
      - `resolved` = baseline keys that no longer fire -> informational (a fix; never required).

    A MISSING baseline file fails CLOSED: with no committed acceptance, every fresh violation is
    unaccepted and the site must be seeded first (a hollow 'no new violations' when nothing was
    ever baselined would be a fail-open). rc is 1 even when the fresh set is empty, so an unseeded
    site cannot pass by happening to be clean -- seeding is an explicit, reviewed act."""
    new = sorted(fresh - baseline)
    resolved = sorted(baseline - fresh)
    if not baseline_present:
        return 1, sorted(fresh), []
    return (1 if new else 0), new, resolved


def resolve_axe_source() -> Optional[str]:
    """Locate axe.min.js: AXE_SOURCE (the sandbox driver sets it), else the npm global roots where
    `npm install -g axe-core` lands it. None when absent -> an env-unmet SKIP, not a FAIL."""
    env = os.environ.get("AXE_SOURCE")
    if env and os.path.isfile(env):
        return env
    for candidate in ("/usr/local/lib/node_modules/axe-core/axe.min.js",
                      "/usr/lib/node_modules/axe-core/axe.min.js"):
        if os.path.isfile(candidate):
            return candidate
    return None


# axe.run over the LIVE document, violations only (passes/incomplete/inapplicable are not gated).
# An async arrow so page.evaluate awaits the axe promise.
_AXE_RUN_JS = (
    "async () => { const r = await axe.run(document, "
    "{resultTypes: ['violations']}); return r.violations; }")

# Force every `content-visibility: auto` section to render before axe measures. That CSS defers
# rendering (and layout/paint) of OFF-SCREEN content as a perf win, but axe-core then samples
# color-contrast against an unrendered element's indeterminate background and reports FALSE
# failures (a link that is perfectly legible once scrolled into view). An a11y audit must measure
# RENDERED content. Flip ONLY `auto` -- never `hidden`, which intentionally drops content from
# rendering AND the a11y tree (forcing that visible would audit unreachable content). Set each such
# element's own style via CSSOM: a property assignment, not markup, so it is unaffected by the
# page's strict style-src CSP (the same reason axe-core is injected by evaluate, not a <script>).
# Set it `important` so an author `content-visibility: auto !important` (which would otherwise beat
# a normal inline declaration and keep the element unrendered) is still overridden.
_FORCE_RENDER_JS = (
    "() => { try { for (const el of document.querySelectorAll('*')) { "
    "if (getComputedStyle(el).contentVisibility === 'auto') { "
    "el.style.setProperty('content-visibility', 'visible', 'important'); } } } catch (e) {} }")


async def _axe_page(browser, url: str, axe_src: str, settle_ms: int) -> dict:
    """Load one page, inject axe-core, run it, return its violations. Own close is time-boxed so a
    wedged page cannot hang here -- the caller ALSO wraps this in a hard wall-clock timeout.

    axe-core is injected by EVALUATING its source (page.evaluate), NOT add_script_tag: the family
    sites ship a strict `script-src 'self'` CSP (exactly what the console lane guards), which
    blocks an injected inline <script> tag. page.evaluate runs via CDP, outside the page's CSP, so
    axe installs regardless -- the only injection that works against the hardened sites."""
    from urllib.parse import urlparse
    allowed = urlparse(url).netloc
    nav: Dict[str, Any] = {"count": 0, "redirect": None}
    page = await browser.new_page()

    async def _hermetic(route):
        # A redirect stub (meta-refresh / JS) issues a SECOND main-frame navigation after the page
        # we asked for -- to a SAME-ORIGIN target (/wiki/Design, a 404 when that target is absent),
        # or to an absolute off-mount url (PRODUCTION www.kicksecure.com, whose old-MediaWiki DOM
        # then leaks Prism/cookiewarning/toctogglecheckbox ghosts). Following it audits the TARGET
        # and mis-attributes its a11y to this stub. Allow ONLY the first main-frame navigation (the
        # requested page); treat any later one as a redirect and SKIP (the target is a real page
        # audited on its own). Separately, abort any OFF-MOUNT subresource so the audit stays
        # hermetic (never fetch off the local mount).
        req = route.request
        if req.is_navigation_request() and req.frame == page.main_frame:
            nav["count"] += 1
            if nav["count"] == 1:
                await route.continue_()
                return
            nav["redirect"] = req.url
            await route.abort()
            return
        if urlparse(req.url).netloc == allowed:
            await route.continue_()
        else:
            await route.abort()

    await page.route("**/*", _hermetic)
    try:
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=45000)
        except Exception:
            # A blocked redirect navigation can surface as a main-frame navigation error -- that is
            # the redirect-stub case, not a wedge. Re-raise anything else (a real load failure).
            if nav["redirect"]:
                return {"redirect": nav["redirect"]}
            raise
        if nav["redirect"]:
            return {"redirect": nav["redirect"]}
        # Playwright does NOT raise on a 404/500; without this a served error page reads as
        # auditable and a missing/broken page is silently 'clean'.
        status = resp.status if resp is not None else 0
        if status < 200 or status >= 400:
            return {"status": status}
        await page.evaluate(_FORCE_RENDER_JS)
        await page.wait_for_timeout(settle_ms)
        # A delayed meta-refresh (content="N") can fire DURING settle: _hermetic aborts + records it,
        # so re-check here -- else axe would run on the stub and report its a11y as a real page.
        if nav["redirect"]:
            return {"redirect": nav["redirect"]}
        await page.evaluate(axe_src)
        violations = await page.evaluate(_AXE_RUN_JS)
        return {"status": status, "violations": violations}
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=5)
        except Exception:
            # Best-effort teardown: a page that already crashed/closed (or hangs on close) must
            # not mask the audit result or the real exception in flight. Nothing to recover.
            pass


async def check(base: str, paths: List[str], axe_source: str, settle_ms: int = 1000,
                hard_timeout: int = 55) -> Tuple[Set[Key], List[str]]:
    """Audit every page served at `base`, returning (fresh_keys, problems). A problem (a wedged
    page, a bad HTTP status) is a hard fault the caller fails on -- an unauditable page is never a
    silent clean. No retries: a localhost mount is deterministic (mirrors check_roots' retries=0
    rationale in the sibling console lane)."""
    from playwright.async_api import async_playwright

    keys: Set[Key] = set()
    problems: List[str] = []
    # Read the axe-core source ONCE (injected per page via page.evaluate -- see _axe_page). A read
    # error here is a real env fault, not a clean result, so let it propagate.
    axe_src = Path(axe_source).read_text(encoding="utf-8")
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as exc:          # noqa: BLE001 -- engine not installed
            # python3-playwright present but the chromium ENGINE absent is env-unmet. Surface it to
            # the caller, which SKIP(77)s only if nothing has been audited yet; a launch failure
            # after an earlier docroot already ran is a mid-run fault, not a silent SKIP.
            raise _EngineUnavailable(str(exc)) from exc
        for path in paths:
            url = base.rstrip("/") + "/" + path.lstrip("/")
            try:
                res = await asyncio.wait_for(
                    _axe_page(browser, url, axe_src, settle_ms), timeout=hard_timeout)
            except Exception:
                # This page wedged -> recreate the browser so the wedge does not cascade.
                try:
                    await asyncio.wait_for(browser.close(), timeout=5)
                except Exception:
                    # This page's audit failed (timeout, navigation or evaluation error); a close
                    # that also errors or hangs does not change recovery. Discard this browser and
                    # relaunch a clean one below so the failure cannot cascade to later pages.
                    pass
                browser = await p.chromium.launch()
                print("TIMEOUT   %s" % path, flush=True)
                problems.append("wedged: %s" % path)
                continue
            if res.get("redirect"):
                # A redirect stub (meta-refresh off-mount); not an auditable content page. Its
                # target is a real page audited on its own. Skip -- never a violation or a problem.
                print("redir     %s" % path, flush=True)
                continue
            status = res.get("status", 0)
            if status < 200 or status >= 400:
                print("HTTP %-4d %s" % (status, path), flush=True)
                problems.append("bad status %d: %s" % (status, path))
                continue
            page_keys = result_keys(path, res.get("violations", []))
            print("%-9s %3d %s" % ("viol" if page_keys else "ok", len(page_keys), path),
                  flush=True)
            for _path, rule, target in page_keys:
                print("          -> %s @ %s" % (rule, _safe_terminal(target[:200])), flush=True)
            keys.update(page_keys)
        try:
            await asyncio.wait_for(browser.close(), timeout=5)
        except Exception:
            # Best-effort final teardown: the audit is already complete and its keys are captured;
            # a close that errors/hangs here must not turn a clean run into a failure. Nothing to do.
            pass
    return keys, problems


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    """Per-site baseline file, keyed by the checkout's basename."""
    return baseline_dir / ("axe-baseline-%s.txt" % os.path.basename(os.path.normpath(root)))


def _ignore_path(baseline_dir: Path, root: str) -> Path:
    """Per-site axe ignore-list (mirrors vnu's vnu-ignore-<site>.txt): pages EXCLUDED from the a11y
    gate ENTIRELY -- not audited, not baselined. For generator demo/test FIXTURES whose job is to
    DISPLAY rejected/demo states (auditing them for contrast is a category error, not a baseline).
    ENUMERATED pages only; a real /wiki/ content page is never excluded, so a regression still reds."""
    return baseline_dir / ("axe-ignore-%s.txt" % os.path.basename(os.path.normpath(root)))


def parse_axe_ignore(text: str) -> Set[str]:
    """One built-tree-relative path per line (blank / '#' skipped), canonicalised (extensionless, no
    leading slash) so an entry like `wiki/Dev/wikitest.html` matches the audited URL path form."""
    out: Set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith('#'):
            out.add(_canon_path(line).lstrip('/'))
    return out


def _load_axe_ignore(baseline_dir: str, root: str) -> Set[str]:
    """The ignore set for a root, or empty if no ignore file is committed (so absence = audit all)."""
    ipath = _ignore_path(Path(baseline_dir), root)
    return parse_axe_ignore(ipath.read_text(encoding='utf-8')) if ipath.is_file() else set()


def _docroots(roots: List[str]) -> Dict[str, dict]:
    """Group roots into docroots exactly like console/mobile main(): a top-level site serves
    itself; a subsite is mounted under its parent's docroot at its mount path (skipped if the
    parent is not checked out)."""
    by_name = {os.path.basename(r): r for r in roots}
    docroots: Dict[str, dict] = {}
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
    return docroots


def _load_paths_file(path: str) -> List[str]:
    """Root-relative audit paths (one per line, blank / '#' skipped) for a CURATED sample -- so a
    huge tree (the ~9000-page wikis) is gated on a representative subset instead of every page."""
    out: List[str] = []
    for raw in Path(path).read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def _restrict_baseline(baseline: Set[Key], restrict: Optional[List[str]]) -> Set[Key]:
    """For a curated (restricted) CHECK: compare only the AUDITED paths' baseline keys, so an
    unvisited page's accepted violation is not misreported 'resolved' (its page was never run)."""
    if restrict is None:
        return baseline
    paths = {_canon_path(p) for p in restrict}
    return {k for k in baseline if k[0] in paths}


def _merge_seed(existing: Set[Key], fresh: Set[Key], restrict: Optional[List[str]]) -> Set[Key]:
    """For a curated (restricted) SEED: keep accepted entries on pages NOT audited and replace only
    the audited paths' keys -- a restricted re-seed must never discard an unvisited page's baseline.
    A full (unrestricted) seed replaces the whole set."""
    if restrict is None:
        return fresh
    paths = {_canon_path(p) for p in restrict}
    return {k for k in existing if k[0] not in paths} | fresh


def _serve_and_audit(docroot: str, entry: dict, axe_source: str, settle_ms: int,
                     hard_timeout: int, restrict: Optional[List[str]] = None,
                     ignore: Optional[Set[str]] = None) -> Tuple[Set[Key], List[str], int]:
    """Serve one docroot on a localhost mount (reusing mobile.py's harness) and audit its pages.
    `restrict` (a curated path list) overrides the enumerated tree -- audit only those paths.
    `ignore` (canonicalised paths) drops enumerated demo/test fixtures from the audit set. Returns
    (keys, problems, excluded) -- excluded is the number ACTUALLY dropped from THIS run's audited
    set (not the ignore-list size), so the caller reports an honest count."""
    handler = functools.partial(_MountHandler, directory=docroot)
    httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
    httpd.mounts = entry['mounts']
    port = httpd.server_address[1]
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = 'http://127.0.0.1:%d' % port
        paths = sorted(set(entry['urls'])) if restrict is None else list(restrict)
        excluded = 0
        if ignore:
            kept = [p for p in paths if _canon_path(p).lstrip('/') not in ignore]
            excluded = len(paths) - len(kept)
            if excluded:
                print("  ....  excluding %d enumerated demo/test fixture(s) (axe-ignore)" % excluded,
                      flush=True)
            paths = kept
        keys, problems = asyncio.run(check(base, paths, axe_source, settle_ms, hard_timeout))
        return keys, problems, excluded
    finally:
        httpd.shutdown()


def check_roots(roots: List[str], baseline_dir: str, settle_ms: int = 1000,
                hard_timeout: int = 55, restrict: Optional[List[str]] = None) -> int:
    """FAMILY/stage entry (run in the sandbox): audit each root vs its committed accepted-violation
    baseline. SKIPs(77) when Playwright/chromium/axe-core is absent. A missing baseline for a root
    fails CLOSED (seed it first)."""
    if restrict is not None and not restrict:
        sys.stderr.write("axe: empty restriction (no paths) -- refusing a vacuous audit\n")
        return 2
    axe_source = resolve_axe_source()
    if axe_source is None:
        _skip('axe-core not found (set AXE_SOURCE or `npm install -g axe-core`)')
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401  (engine launch is inside check())
    except ImportError:
        _skip('python3-playwright not installed')

    overall = 0
    audited = 0
    for docroot, entry in _docroots(roots).items():
        site = os.path.basename(os.path.normpath(docroot))
        ignore = _load_axe_ignore(baseline_dir, docroot)
        try:
            fresh, problems, excluded = _serve_and_audit(docroot, entry, axe_source, settle_ms,
                                                          hard_timeout, restrict, ignore)
        except _EngineUnavailable as exc:
            if audited == 0:
                _skip('chromium engine unavailable: %s' % exc)  # nothing ran -> env-unmet SKIP(77)
            # chromium launched for an earlier docroot but not this one: a mid-run fault, not a
            # silent SKIP. Fail hard and stop -- the remaining docroots cannot run either.
            print("%s: FAIL    chromium engine became unavailable mid-run: %s" % (site, exc),
                  file=sys.stderr)
            overall = 1
            break
        audited += 1
        bpath = _baseline_path(Path(baseline_dir), docroot)
        present = bpath.is_file()
        baseline = parse_baseline(bpath.read_text(encoding="utf-8")) if present else set()
        rc, new, resolved = evaluate(present, _restrict_baseline(baseline, restrict), fresh)
        if not present:
            print("%s: MISSING no baseline %s -- seed with "
                  "'webcheck-axe-sandbox --write-baseline'" % (site, bpath), file=sys.stderr)
        for path, rule, target in new:
            print("%s: NEW     %s %s @ %s"
                  % (site, path, rule, _safe_terminal(target[:200])), file=sys.stderr)
        for path, rule, target in resolved:
            print("%s: fixed   %s %s @ %s (baselined, no longer firing)"
                  % (site, path, rule, _safe_terminal(target[:200])))
        for problem in problems:
            print("%s: FAIL    %s" % (site, problem), file=sys.stderr)
        print("%s: %d accepted, %d fresh, %d NEW, %d resolved, %d problem(s)"
              " (excluded %d enumerated demo/test fixture(s) from this run)"
              % (site, len(baseline), len(fresh), len(new), len(resolved), len(problems),
                 excluded))
        if rc or problems:
            overall = 1
    return overall


def write_roots(roots: List[str], baseline_dir: str, settle_ms: int = 1000,
                hard_timeout: int = 55, restrict: Optional[List[str]] = None) -> int:
    """Seed (overwrite) a per-site baseline from the CURRENT violation set. Refuses to seed a site
    whose pages could not all be audited (a problem) -- a baseline seeded from a half-audited site
    would silently accept nothing for the pages that failed."""
    if restrict is not None and not restrict:
        sys.stderr.write("axe: empty restriction (no paths) -- refusing a vacuous audit\n")
        return 2
    axe_source = resolve_axe_source()
    if axe_source is None:
        _skip('axe-core not found (set AXE_SOURCE or `npm install -g axe-core`)')
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401
    except ImportError:
        _skip('python3-playwright not installed')

    audited = 0
    for docroot, entry in _docroots(roots).items():
        site = os.path.basename(os.path.normpath(docroot))
        ignore = _load_axe_ignore(baseline_dir, docroot)
        try:
            fresh, problems, excluded = _serve_and_audit(docroot, entry, axe_source, settle_ms,
                                                          hard_timeout, restrict, ignore)
        except _EngineUnavailable as exc:
            if audited == 0:
                _skip('chromium engine unavailable: %s' % exc)  # nothing seeded -> env-unmet SKIP(77)
            print("axe: refusing to seed -- chromium became unavailable mid-run after %d site(s): %s"
                  % (audited, exc), file=sys.stderr)
            return 2
        audited += 1
        if problems:
            print("axe: refusing to seed %s -- %d page(s) unauditable: %s"
                  % (site, len(problems), "; ".join(problems)), file=sys.stderr)
            return 2
        bpath = _baseline_path(Path(baseline_dir), docroot)
        Path(baseline_dir).mkdir(parents=True, exist_ok=True)
        # Only a RESTRICTED seed needs the old entries (to keep unvisited pages). An unrestricted
        # seed overwrites wholesale, so do not parse the old baseline -- a malformed existing file
        # must not block replacing it.
        existing: Set[Key] = set()
        if restrict is not None and bpath.is_file():
            existing = parse_baseline(bpath.read_text(encoding="utf-8"))
        seeded = _merge_seed(existing, fresh, restrict)
        bpath.write_text(format_baseline(seeded, site=site), encoding="utf-8")
        print("wrote %d accepted violation(s) -> %s" % (len(seeded), bpath), file=sys.stderr)
    return 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="axe-core accessibility regression gate (local-serve).")
    ap.add_argument("--baseline-dir", required=True,
                    help="dir holding axe-baseline-<site>.txt")
    ap.add_argument("--write-baseline", action="store_true",
                    help="seed/overwrite the baseline from the current violations instead of gating")
    ap.add_argument("--axe-source", default=None,
                    help="path to axe.min.js (else AXE_SOURCE env, else the npm global roots)")
    ap.add_argument("--settle", type=int, default=1000,
                    help="post-load settle time in ms before injecting axe (default 1000)")
    ap.add_argument("--paths-file", default=None,
                    help="restrict the audit to the root-relative paths in this file (one per "
                         "line, blank/# skipped) -- a curated sample instead of the whole tree")
    ap.add_argument("roots", nargs="+", help="site checkout root(s) with index.html")
    args = ap.parse_args(argv)
    if args.axe_source:
        os.environ["AXE_SOURCE"] = args.axe_source
    restrict = None
    if args.paths_file:
        restrict = _load_paths_file(args.paths_file)
        if not restrict:
            sys.stderr.write("axe: --paths-file '%s' has no paths -- refusing to fall back to a "
                             "full-tree audit (omit the flag for a full audit)\n" % args.paths_file)
            return 2
    if args.write_baseline:
        return write_roots(args.roots, args.baseline_dir, args.settle, restrict=restrict)
    return check_roots(args.roots, args.baseline_dir, args.settle, restrict=restrict)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
