## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Runtime gate: NO page forces a SYNCHRONOUS REFLOW from our own JavaScript during load --
the same thing PageSpeed Insights / Lighthouse report as "Forced reflow" / "Avoid forced reflow"
(the `total reflow time` insight derived from the DevTools performance trace).

Generic webcheck lane, shared by the family Pages sites and the wiki stage sites. PageSpeed has
no separate tool for this: it loads the page under a trace and sums the `Layout` /
`UpdateLayoutTree` events that carry a JS stack -- i.e. layout the browser was FORCED to compute
synchronously because a script read a geometric property (offsetWidth, scrollWidth,
getBoundingClientRect, getComputedStyle, ...) while layout was dirty -- attributing each to the
script frame on top of its stack. A forced reflow is pure main-thread waste: the browser recomputes
layout mid-script instead of once per frame. This lane reproduces exactly that: it captures the
same trace categories, finds the same forced-layout events, and FAILS (exit 1) when any is
attributed to a FIRST-PARTY script (a frame served from the page's own origin). The strict CSP
ships no third-party JS, so in practice every JS-attributed forced layout on these sites is ours.

A static check cannot see this (it is a runtime, trace-level signal) and jsdom has no layout
engine, so -- like the console / mobile / width lanes -- it loads each page in a real headless
chromium. Two page-source models share the one async core `check(base, paths, ...)`:
  - FAMILY (local): `check_roots(roots)` serves each site checkout from a localhost mount
    (reusing mobile.py's harness) and points `base` at it -- the model the website-tests browser
    lanes use. No network, no external build.
  - STAGE (served): `main()` drives `--base <url>` (or `--serve-tree <dir>`, which serves a built
    tree on localhost itself) with `--paths/--paths-file/--enumerate-from` against a built site.

Mobile is the PageSpeed-flagged form (4x CPU throttle, like Lighthouse mobile); desktop runs too
(1x) because a reflow can be viewport-specific. A page FAILS if EITHER viewport attributes a forced
layout to first-party JS above the budget (default 0: our load path must force no synchronous
layout). Needs a browser; against untrusted input it runs CONFINED in the sandbox. The browser-free
logic (forced-event detection, stack attribution, first-party test, URL join, path enumeration) is
unit-tested.
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from dist_ai.webcheck.mobile import (
    _MountHandler, _MountingTCPServer, _page_urls, _skip, SUBSITES)

# Lighthouse mobile user agent (Moto G Power), paired with is_mobile + has_touch in the mobile
# context so a reflow gated on navigator.userAgent / a touch or pointer query -- which PageSpeed
# mobile WOULD trigger -- is not silently missed under a desktop UA.
_MOBILE_UA = ("Mozilla/5.0 (Linux; Android 11; moto g power (2022)) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36")

_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe_terminal(s) -> str:
    """Strip C0/C1 control bytes from any UNTRUSTED string -- a checked page's path, a trace frame's
    function name, an exception message -- before printing it, so a crafted site (or a title crafted
    into a trace frame) cannot emit OSC-52 / ANSI to rewrite the operator's clipboard or forge gate
    output. Mirrors the console lane's identical terminal-safety guard."""
    return _CTRL_CHARS.sub("?", str(s))

# Mirror the console / mobile / check-cls viewports so every browser gate measures the same two
# renders. The CPU throttle matches Lighthouse: mobile emulates a slow phone (4x), desktop a fast
# machine (1x). Forced-layout TIME scales with the throttle; the COUNT we gate on does not -- a
# read-after-write forces one layout whatever the clock rate.
_VIEWPORTS = (
    ("mobile", 412, 915, 1.75, 4),    # Lighthouse Moto G Power, 4x CPU slowdown
    ("desktop", 1350, 940, 1.0, 1),   # Lighthouse desktop, no CPU slowdown
)

# The trace categories PageSpeed/Lighthouse use. `...timeline.stack` is what attaches the JS stack
# to a Layout event -- without it a forced (script-triggered) layout is indistinguishable from a
# pipeline layout the renderer does once per frame.
_TRACE_CATEGORIES = ",".join((
    "devtools.timeline",
    "disabled-by-default-devtools.timeline",
    "disabled-by-default-devtools.timeline.stack",
))

# A forced synchronous layout is one of these trace events carrying a JS stack. 'Layout' = forced
# reflow (a script read box geometry); 'UpdateLayoutTree' = forced style recalc (a script read a
# computed style). A pipeline (non-forced) layout has NO JS stack and is not counted.
_FORCED_EVENTS = frozenset({"Layout", "UpdateLayoutTree"})


def page_url(base: str, path: str) -> str:
    """Join base origin + page path, tolerating a path without its leading slash."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def is_off_origin(final_url: str, base_url: str) -> bool:
    """True when a page ended up on a DIFFERENT HOST than the base -- a meta-refresh stub that
    redirects to a third-party site, whose reflow is not ours to gate. Host-only compare (a
    http->https upgrade or an explicit-vs-implicit default port is still our content)."""
    return (urlsplit(final_url).hostname or "").lower() \
        != (urlsplit(base_url).hostname or "").lower()


def is_first_party(frame_url: str, base_url: str) -> bool:
    """True when a stack frame's script is served from the PAGE'S OWN ORIGIN (host). First-party JS
    forcing a layout is OURS to fix; a browser-internal frame (no url) or a hypothetical 3p script
    is not gated. Host-only, matching is_off_origin, so a localhost mount on any port qualifies."""
    if not frame_url:
        return False
    host = (urlsplit(frame_url).hostname or "").lower()
    return host != "" and host == (urlsplit(base_url).hostname or "").lower()


def _event_stack(ev):
    """The JS stack attached to a forced-layout trace event, or None if it was not forced.
    'Layout' carries it under args.beginData.stackTrace; 'UpdateLayoutTree' under args.stackTrace."""
    args = ev.get("args") or {}
    begin = args.get("beginData") or {}
    if isinstance(begin, dict) and begin.get("stackTrace"):
        return begin["stackTrace"]
    if args.get("stackTrace"):
        return args["stackTrace"]
    return None


def _frame_label(frame) -> str:
    """'file.js:line:col (function)' for a stack frame, the script basename without its ?h= buster
    so the attribution is stable across a fingerprint change."""
    url = frame.get("url") or ""
    return "%s:%s:%s (%s)" % (
        url.rsplit("/", 1)[-1].split("?", 1)[0] or "(inline)",
        frame.get("lineNumber", "?"),
        frame.get("columnNumber", "?"),
        frame.get("functionName") or "(anonymous)",
    )


def _stable_frame(frame_label: str) -> str:
    """A frame_label with the :line:col dropped, so a baseline key survives an unrelated edit that
    shifts the offending line. 'file.js:168:93 (sync)' -> 'file.js (sync)'."""
    head, sep, func = frame_label.partition(" (")
    script = head.rsplit(":", 2)[0]
    return script + sep + func if sep else script


def baseline_key(path: str, frame_label: str) -> str:
    """Stable identity of one accepted forced reflow: '<page path>\\t<script (function)>'. Line/col
    excluded so the key does not churn on every unrelated edit; path included so the same helper on
    two pages is two independent entries to burn down."""
    return path + "\t" + _stable_frame(frame_label)


def load_baseline(path: Path) -> frozenset:
    """Accepted-finding keys from a baseline file (blank + '#'-comment lines ignored). A missing
    file means no accepted findings -> budget-0 clean required (the common, desired state)."""
    if not path.is_file():
        return frozenset()
    return frozenset(
        ln.rstrip("\n") for ln in path.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#"))


def write_baseline(path: Path, keys) -> None:
    """(Re)write a site's baseline from the keys a record run observed. One key per line, sorted."""
    path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# forced-reflow baseline: accepted pre-existing first-party forced reflows for this site,\n"
        "# one per line as '<path>\\t<script (function)>'. The gate FAILS only on a NEW forced\n"
        "# reflow not listed here; a listed page+frame is reported KNOWN, not a failure. Burn this\n"
        "# list down (fix the reflow, drop the line). Regenerate after a deliberate change with\n"
        "# WEBCHECK_UPDATE_FORCED_REFLOW_BASELINE=1.\n")
    path.write_text(header + "".join(k + "\n" for k in sorted(keys)))


def attribute_forced_layouts(events, base_url: str):
    """From raw trace events, the first-party forced layouts as (frame_label, duration_ms) pairs.
    A non-forced layout (no JS stack) or one whose top JS frame is not first-party is excluded, so
    the gate judges only reflow OUR OWN code forced. Pure (no browser) -> unit tested."""
    out = []
    for ev in events:
        if ev.get("name") not in _FORCED_EVENTS:
            continue
        stack = _event_stack(ev)
        if not stack:
            continue  # pipeline layout, not forced by script
        top = next((f for f in stack if f.get("url")), None)
        if top is None or not is_first_party(top.get("url") or "", base_url):
            continue  # browser-internal or third-party frame -- not ours
        out.append((_frame_label(top), ev.get("dur", 0) / 1000.0))
    return out


def enumerate_paths(tree: Path):
    """Every built page under the FLAT tree: root index.html -> "/", and every wiki/<...>.html
    served at the extensionless /wiki/<...>. Recursive (a nested title is included)."""
    paths = ["/"] if (tree / "index.html").is_file() else []
    wiki = tree / "wiki"
    if wiki.is_dir():
        for page in sorted(wiki.rglob("*.html")):
            if page.is_file():
                paths.append("/wiki/" + page.relative_to(wiki).as_posix().removesuffix(".html"))
    return paths


async def _probe(browser, url, settle_ms, base_url, viewport):
    """(forced_list, total_ms) for one page at one viewport, or {'external': url} / {'bad_status':
    N}. forced_list is the first-party forced layouts; total_ms their summed duration. A trace is
    captured via CDP exactly as Lighthouse does."""
    _label, vw, vh, dpr, cpu = viewport
    ctx_kwargs = {"viewport": {"width": vw, "height": vh}, "device_scale_factor": dpr}
    if _label == "mobile":
        ctx_kwargs.update(is_mobile=True, has_touch=True, user_agent=_MOBILE_UA)
    ctx = await browser.new_context(**ctx_kwargs)
    try:
        page = await ctx.new_page()
        cdp = await ctx.new_cdp_session(page)
        collected: list = []
        complete = asyncio.Event()
        # A trace is only trustworthy once tracingComplete fires AND reports no data loss: ReportEvents
        # can still drop events (buffer wrap), and a never-arriving tracingComplete means dataCollected
        # may be truncated. Either way a forced Layout could be the missing event, so track both and
        # fail CLOSED below rather than read a partial/lossy trace as a clean PASS.
        trace = {"loss": False, "done": False}
        loop = asyncio.get_event_loop()
        cdp.on("Tracing.dataCollected", lambda p: collected.extend(p.get("value", [])))

        def _on_complete(payload):
            trace["loss"] = bool((payload or {}).get("dataLossOccurred"))
            trace["done"] = True
            loop.call_soon_threadsafe(complete.set)

        cdp.on("Tracing.tracingComplete", _on_complete)
        if cpu > 1:
            await cdp.send("Emulation.setCPUThrottlingRate", {"rate": cpu})
        await cdp.send("Tracing.start",
                       {"categories": _TRACE_CATEGORIES, "transferMode": "ReportEvents"})
        resp = await page.goto(url, wait_until="load", timeout=45000)
        status = resp.status if resp is not None else 0
        if status < 200 or status >= 400:
            await cdp.send("Tracing.end")
            return {"bad_status": status}
        # Let the deferred (requestIdleCallback) widgets and their rAF/ResizeObserver measurements
        # run -- that is when a load-path forced reflow lands.
        await page.wait_for_timeout(settle_ms)
        final = page.url
        await cdp.send("Tracing.end")
        try:
            await asyncio.wait_for(complete.wait(), timeout=20)
        except asyncio.TimeoutError:
            pass
        if is_off_origin(final, base_url):
            return {"external": final}
        if trace["loss"] or not trace["done"]:
            return {"trace_bad": "data loss" if trace["loss"] else "tracingComplete never arrived"}
        forced = attribute_forced_layouts(collected, base_url)
        return {"forced": forced, "ms": sum(d for _f, d in forced)}
    finally:
        try:
            await asyncio.wait_for(ctx.close(), timeout=5)
        except Exception:
            pass


async def check(base, paths, settle_ms=3000, budget=0, hard_timeout=70,
                accepted=frozenset(), record_into=None):
    from playwright.async_api import async_playwright
    bad = 0
    wedged: list = []
    external: list = []
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as exc:          # noqa: BLE001 -- engine not installed
            _skip('chromium engine unavailable: %s' % exc)
        try:
            for path in paths:
                url = page_url(base, path)
                results = []
                wedge = ext = False
                for viewport in _VIEWPORTS:
                    label = viewport[0]
                    try:
                        res = await asyncio.wait_for(
                            _probe(browser, url, settle_ms, base, viewport), timeout=hard_timeout)
                    except Exception as e:  # noqa: BLE001 -- a wedge must fail, not pass
                        wedge = True
                        print("WEDGE     %s [%s]: %s: %s"
                              % (safe_terminal(path), label, type(e).__name__, safe_terminal(e)),
                              flush=True)
                        try:
                            await asyncio.wait_for(browser.close(), timeout=5)
                        except Exception:
                            pass
                        browser = await p.chromium.launch()
                        continue
                    if "external" in res:
                        ext = True
                        continue
                    if "bad_status" in res:
                        print("HTTP %-4s %s [%s]" % (res["bad_status"], safe_terminal(path), label),
                              flush=True)
                        wedge = True
                        continue
                    if "trace_bad" in res:
                        print("TRACE?    %s [%s]: %s -- failing closed"
                              % (safe_terminal(path), label, res["trace_bad"]), flush=True)
                        wedge = True
                        continue
                    results.append((label, res["forced"], res["ms"]))
                # A page that wedged on EITHER viewport fails even if the other redirected off-origin:
                # the external short-circuit fires only when nothing else went wrong, so a real error
                # (HTTP 500, lossy trace, hang) is never masked by an external redirect on the sibling.
                if ext and not results and not wedge:
                    print("REDIR-EXT %s" % safe_terminal(path), flush=True)
                    external.append(path)
                    continue
                # Split each viewport's forced layouts into KNOWN (baselined -- accepted, not a
                # failure) and NEW (gated). record_into, when set, collects every key so a refresh
                # run can rewrite the baseline from exactly what is present.
                offenders = False
                annotated = []  # (vp, new_list, known_count, ms)
                for vp, forced, ms in results:
                    new, known = [], 0
                    for frame, dur in forced:
                        key = baseline_key(path, frame)
                        if record_into is not None:
                            record_into.add(key)
                        if key in accepted:
                            known += 1
                        else:
                            new.append((frame, dur))
                    annotated.append((vp, new, known, ms))
                    if len(new) > budget:
                        offenders = True
                mark = "FORCED" if offenders else "ok"
                print("%-6s %s" % (mark, safe_terminal(path)), flush=True)
                for vp, new, known, _ms in annotated:
                    if known:
                        print("          [%s] %d KNOWN baselined forced layout(s)" % (vp, known),
                              flush=True)
                    if new:
                        print("          [%s] %d forced layout(s), %.1f ms"
                              % (vp, len(new), sum(d for _f, d in new)), flush=True)
                        for frame, dur in new:
                            print("            -> %6.1f ms  %s" % (dur, safe_terminal(frame)),
                                  flush=True)
                # One failing page counts ONCE (the summary is a page count), whatever mix of a wedge
                # and a NEW forced layout it hit. A wedge always fails; a new forced layout fails
                # unless we are only recording a baseline.
                if wedge or (offenders and record_into is None):
                    bad += 1
        finally:
            try:
                await asyncio.wait_for(browser.close(), timeout=5)
            except Exception:
                pass

    print("\n%d page(s) checked; %d with a first-party forced reflow / wedge, %d external-redirect."
          % (len(paths), bad, len(external)), flush=True)
    if paths and len(external) == len(paths):
        print("ERROR: every page redirected off-origin -- nothing was gated; check the base",
              flush=True)
        return 1
    if bad:
        print("check-forced-reflow: FAIL -- %d page(s) force synchronous layout from first-party "
              "JS (PageSpeed 'forced reflow'). Read layout BEFORE writing, or defer the read to a "
              "ResizeObserver/IntersectionObserver callback (post-layout), never a requestAnimationFrame "
              "(pre-layout)." % bad, flush=True)
        return 1
    print("check-forced-reflow: PASS -- all %d page(s) force no synchronous layout from first-party JS"
          % len(paths), flush=True)
    return 0


def check_roots(roots: list, settle_ms: int = 3000, budget: int = 0, baseline_dir=None) -> int:
    """FAMILY entry: serve each local site checkout from a localhost mount (reusing mobile.py's
    harness, incl. SUBSITES mounting) and run the forced-reflow gate against it. SKIPs (exit 77)
    when Playwright/chromium is absent, exactly like the sibling browser lanes.

    baseline_dir: if given, each served site's pre-existing forced reflows are read from
    <baseline_dir>/<site>.txt and reported KNOWN (the gate fails only on a NEW one). Setting
    WEBCHECK_UPDATE_FORCED_REFLOW_BASELINE=1 REWRITES those files from the current findings."""
    import os
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')
    try:
        import playwright.async_api  # noqa: F401  (engine launch is inside check())
    except ImportError:
        _skip('python3-playwright not installed')

    by_name = {os.path.basename(r): r for r in roots}
    docroots: dict = {}
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

    update = os.environ.get("WEBCHECK_UPDATE_FORCED_REFLOW_BASELINE") == "1"
    overall = 0
    for docroot, entry in docroots.items():
        site = os.path.basename(docroot)
        accepted, baseline_path, record_into = frozenset(), None, None
        if baseline_dir is not None:
            baseline_path = Path(baseline_dir) / (site + ".txt")
            accepted = load_baseline(baseline_path)
            if update:
                record_into = set()
        handler = functools.partial(_MountHandler, directory=docroot)
        httpd = _MountingTCPServer(('127.0.0.1', 0), handler)
        httpd.mounts = entry['mounts']
        port = httpd.server_address[1]
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            base = 'http://127.0.0.1:%d' % port
            paths = sorted(set(entry['urls']))
            rc = asyncio.run(check(base, paths, settle_ms, budget, accepted=accepted,
                                   record_into=record_into))
            if rc != 0:
                overall = 1
        finally:
            httpd.shutdown()
        if record_into is not None and baseline_path is not None:
            write_baseline(baseline_path, record_into)
            print("baseline refreshed: %s (%d accepted finding(s))"
                  % (baseline_path, len(record_into)), flush=True)
    return overall


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_tree(tree: Path):
    """Serve a built tree on a free localhost port via the real pre-deploy-serve.py (try_files,
    mirrors nginx/Pages), so --serve-tree needs no external server. Returns (proc, base_url).
    pre-deploy-serve.py ships beside this core's wiki sibling; locate it on PATH or next to the
    invoking script via $WEBCHECK_SERVE."""
    import os
    serve = os.environ.get("WEBCHECK_SERVE")
    if not serve:
        from shutil import which
        serve = which("pre-deploy-serve.py")
    if not serve or not Path(serve).is_file():
        raise RuntimeError("pre-deploy-serve.py not found; set WEBCHECK_SERVE to its path")
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-Bsu", str(serve), str(port), str(tree)])
    base = "http://127.0.0.1:%d" % port
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return proc, base
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError("pre-deploy-serve.py exited early")
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("pre-deploy-serve.py did not come up on %d" % port)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    origin = ap.add_mutually_exclusive_group(required=True)
    origin.add_argument("--base", help="served site origin, e.g. https://kicksecure-stage.github.io")
    origin.add_argument("--serve-tree", type=Path,
                        help="built tree dir: serve it on localhost and measure (self-contained)")
    ap.add_argument("--settle", type=int, default=3000,
                    help="post-load settle time in ms (covers the rIC-2000 deferral; default 3000)")
    ap.add_argument("--budget", type=int, default=0,
                    help="max forced layouts first-party JS may trigger per page per viewport "
                         "(default 0)")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="accepted-finding file: a listed '<path>\\t<script (function)>' is reported "
                         "KNOWN and the gate fails only on a NEW forced reflow. "
                         "WEBCHECK_UPDATE_FORCED_REFLOW_BASELINE=1 rewrites it from current findings.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--paths", nargs="*", default=None, help="explicit page paths to check")
    src.add_argument("--paths-file", type=Path, default=None, help="file: one page path per line")
    src.add_argument("--enumerate-from", type=Path, default=None,
                     help="a built tree dir: check root + every wiki/<Page>")
    return ap


def main() -> int:
    import os
    ap = build_parser()
    args = ap.parse_args()
    if args.enumerate_from:
        if not args.enumerate_from.is_dir():
            ap.error("--enumerate-from: not a directory: %s" % args.enumerate_from)
        paths = enumerate_paths(args.enumerate_from)
    elif args.paths_file:
        if not args.paths_file.is_file():
            ap.error("--paths-file: not a file: %s" % args.paths_file)
        paths = [ln.strip() for ln in args.paths_file.read_text().splitlines() if ln.strip()]
    else:
        paths = args.paths
    if not paths:
        ap.error("no pages to check")
    proc = None
    try:
        if args.serve_tree:
            if not args.serve_tree.is_dir():
                ap.error("--serve-tree: not a directory: %s" % args.serve_tree)
            proc, base = _serve_tree(args.serve_tree.resolve())
        else:
            base = args.base
        accepted = load_baseline(args.baseline) if args.baseline else frozenset()
        record_into = (set() if args.baseline
                       and os.environ.get("WEBCHECK_UPDATE_FORCED_REFLOW_BASELINE") == "1"
                       else None)
        rc = asyncio.run(check(base, paths, args.settle, args.budget,
                               accepted=accepted, record_into=record_into))
        if record_into is not None:
            write_baseline(args.baseline, record_into)
            print("baseline refreshed: %s (%d accepted finding(s))"
                  % (args.baseline, len(record_into)), flush=True)
        return rc
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
