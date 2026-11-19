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
layout mid-script instead of once per frame. This lane captures the same trace categories and finds
the same forced-layout events, and FAILS (exit 1) when any is attributed to a FIRST-PARTY script (a
frame served from the page's own origin). It is deliberately STRICTER than the DevTools "total
reflow time" insight, NOT an exact reproduction of its verdict: the budget is 0 (any single
first-party forced layout fails), whereas the DevTools insight counts only forced events nested
inside a JavaScript task and surfaces a warning at a 30 ms per-task threshold. So this gate can fail
a page the DevTools panel would not flag; that is intentional (we hold our own load path to zero
forced synchronous layout). The strict CSP ships no third-party JS, so in practice every
JS-attributed forced layout on these sites is ours.

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
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

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
    """'<script url path>:line:col (function)' for a stack frame. The script's full URL PATH (its
    pathname, not just the basename) names the offender, so two same-named scripts under different
    directories ('/a/ui.js' vs '/b/ui.js') are reported distinctly. The ?h= cache buster (the query)
    is dropped via urlsplit so the attribution is stable across a fingerprint change."""
    url = frame.get("url") or ""
    return "%s:%s:%s (%s)" % (
        urlsplit(url).path or "(inline)",
        frame.get("lineNumber", "?"),
        frame.get("columnNumber", "?"),
        frame.get("functionName") or "(anonymous)",
    )


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
                # Percent-encode the FILESYSTEM name before using it as a URL path (preserving the
                # '/' separators): a title like 'Example#Notes.html' would otherwise become
                # '/wiki/Example#Notes', where the browser drops '#Notes' as a fragment and requests
                # '/wiki/Example' -- the gate would silently measure the wrong page. Explicit CLI
                # --paths are left verbatim (the operator typed a real URL path).
                rel = page.relative_to(wiki).as_posix().removesuffix(".html")
                paths.append("/wiki/" + quote(rel, safe="/"))
    return paths


def classify_probe(collected, base_url, initial_status, final_url, final_nav_status, trace):
    """Pure post-settle verdict for one page/viewport, split out of _probe so the gate's PASS/FAIL
    decision is browser-free unit-tested. Inputs: the raw trace `collected` during settle, the page
    origin `base_url`, the HTTP `initial_status` goto() returned, the `final_url` after settle, the
    status of the LAST main-frame navigation response during settle (`final_nav_status`, or None if
    none fired past the initial load), and `trace` = {'loss','done'} from tracingComplete. Returns:
      {'trace_bad': why}                       -- incomplete/lossy capture: fail CLOSED (a forced
                                                   Layout could be the dropped event)
      {'external': url, 'forced': [...], 'ms'} -- ended off-host; first-party forced layouts
                                                   captured BEFORE the redirect STILL gate, so a page
                                                   that thrashes layout then redirects away cannot
                                                   hide behind the external short-circuit
      {'bad_status': N}                        -- a same-host document (the initial one, OR a
                                                   post-load client redirect to a same-host error)
                                                   returned an HTTP error -- never read as a pass
      {'forced': [...], 'ms': N}               -- a clean same-host measurement"""
    if trace.get("loss") or not trace.get("done"):
        return {"trace_bad": "data loss" if trace.get("loss") else "tracingComplete never arrived"}
    forced = attribute_forced_layouts(collected, base_url)
    ms = sum(d for _f, d in forced)
    # A FAILED navigation (a client redirect to a 404/download/unreachable target) leaves Chromium on
    # its error page chrome-error://chromewebdata/. That URL is off-host, so the external branch below
    # would read a BROKEN page as a benign off-site redirect and PASS it. A chrome-error final document
    # loaded no real content -- fail CLOSED on the triggering status.
    if final_url.startswith("chrome-error:"):
        return {"bad_status": final_nav_status if final_nav_status is not None else initial_status}
    if is_off_origin(final_url, base_url):
        return {"external": final_url, "forced": forced, "ms": ms}
    # Same host: validate the FINAL document, not just the one goto() first saw. A 200 page that
    # client-redirects during the settle window to a same-host 404 would otherwise be measured as a
    # quiet error page and pass; judge the last main-frame navigation when one fired.
    status = final_nav_status if final_nav_status is not None else initial_status
    if status < 200 or status >= 400:
        return {"bad_status": status}
    return {"forced": forced, "ms": ms}


async def _probe(browser, url, settle_ms, base_url, viewport):
    """The raw post-settle verdict dict for one page at one viewport (see classify_probe for the
    shapes). Captures a CDP trace exactly as Lighthouse does and records main-frame navigation
    responses during the settle window so a post-load redirect to a same-host error is caught."""
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
        # fail CLOSED (via classify_probe) rather than read a partial/lossy trace as a clean PASS.
        trace = {"loss": False, "done": False}
        loop = asyncio.get_event_loop()
        cdp.on("Tracing.dataCollected", lambda p: collected.extend(p.get("value", [])))

        def _on_complete(payload):
            trace["loss"] = bool((payload or {}).get("dataLossOccurred"))
            trace["done"] = True
            loop.call_soon_threadsafe(complete.set)

        cdp.on("Tracing.tracingComplete", _on_complete)
        # Track the LAST main-frame navigation response. The initial goto() response is one such
        # event; a client redirect during settle fires another, whose status then wins -- so a
        # same-host error page reached after load is judged on, not hidden behind the first 200.
        nav = {"status": None}

        def _on_response(resp_obj):
            try:
                req = resp_obj.request
                if req.is_navigation_request() and req.frame == page.main_frame:
                    nav["status"] = resp_obj.status
            except Exception:
                # Best-effort nav tracking: a response we cannot introspect is not a gate signal,
                # and classify_probe still fails closed on an incomplete trace / validates the
                # initial status, so a missed update never turns a real error into a pass.
                pass

        page.on("response", _on_response)
        if cpu > 1:
            await cdp.send("Emulation.setCPUThrottlingRate", {"rate": cpu})
        await cdp.send("Tracing.start",
                       {"categories": _TRACE_CATEGORIES, "transferMode": "ReportEvents"})
        resp = await page.goto(url, wait_until="load", timeout=45000)
        status = resp.status if resp is not None else 0
        if status < 200 or status >= 400:
            await cdp.send("Tracing.end")
            try:
                await asyncio.wait_for(complete.wait(), timeout=20)
            except asyncio.TimeoutError:
                # The error page already decides the verdict (bad_status -> wedge). Awaiting the
                # completion event here only keeps the shared browser's trace from still flushing
                # when the next viewport calls Tracing.start; a timeout just means teardown is slow.
                pass
            return {"bad_status": status}
        # Let the deferred (requestIdleCallback) widgets and their rAF/ResizeObserver measurements
        # run -- that is when a load-path forced reflow lands.
        await page.wait_for_timeout(settle_ms)
        final = page.url
        await cdp.send("Tracing.end")
        try:
            await asyncio.wait_for(complete.wait(), timeout=20)
        except asyncio.TimeoutError:
            # Fall through: classify_probe fails CLOSED while trace['done'] is still False.
            pass
        return classify_probe(collected, base_url, status, final, nav["status"], trace)
    finally:
        try:
            await asyncio.wait_for(ctx.close(), timeout=5)
        except Exception:
            # Best-effort context teardown; a close failure must not mask the page's verdict.
            pass


def _is_engine_absent(exc) -> bool:
    """True only when a chromium launch failed because the ENGINE is not installed -- the sole case
    that justifies a SKIP (exit 77), mirroring check_roots' python3-playwright ImportError skip. Any
    OTHER launch failure (a timeout, a sandbox/namespace error, a crash) is a real failure to REPORT,
    never a silent skip that lets the gate pass unrun. Playwright's not-installed error names the
    missing executable and the `playwright install` remedy."""
    msg = str(exc).lower()
    # "playwright install-deps" is the install-OS-LIBRARIES remedy: the chromium binary IS present
    # but the host lacks shared libs -- a real failure to REPORT, not an absent engine. It contains
    # the "playwright install" substring, so exclude it before the absent-engine match below.
    if "install-deps" in msg:
        return False
    return ("executable doesn't exist" in msg
            or "playwright install" in msg
            or "looks like playwright was just installed" in msg)


async def _launch(p):
    """Launch chromium for the gate. Playwright defaults chromium_sandbox=False; we enable Chromium's
    own namespace sandbox so the renderer that loads UNTRUSTED page content is confined as defense in
    depth. Used by BOTH the initial launch and the wedge-recovery relaunch, so neither path drops the
    sandbox. (The lane also runs under the outer bwrap/sandbox qube for untrusted input; this is the
    inner, per-renderer layer.)"""
    return await p.chromium.launch(chromium_sandbox=True)


async def check(base, paths, settle_ms=3000, budget=0, hard_timeout=70):
    if not paths:
        # An existing but HTML-less site yields zero pages; nothing was gated, so this is NOT a pass.
        # Checked before importing/launching the browser so an empty run fails fast (and testably).
        print("check-forced-reflow: FAIL -- no pages to check (empty page list); nothing was gated",
              flush=True)
        return 1
    from playwright.async_api import async_playwright
    bad = 0
    external: list = []
    async with async_playwright() as p:
        try:
            browser = await _launch(p)
        except Exception as exc:          # noqa: BLE001
            if _is_engine_absent(exc):
                _skip('chromium engine unavailable: %s' % exc)
            # A launch failure with the engine PRESENT (timeout, sandbox/namespace error) is a real
            # error, not an absent-engine skip: fail loud rather than exit 77 and read as "no browser".
            raise RuntimeError("chromium launch failed (engine present): %s" % exc) from exc
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
                            # Best-effort close of the wedged browser before relaunching; a failure
                            # here is immaterial -- the fresh _launch below is what must succeed.
                            pass
                        browser = await _launch(p)
                        continue
                    if "external" in res:
                        ext = True
                        # First-party forced layouts captured BEFORE an off-host redirect STILL gate:
                        # a page that thrashes layout in its own script then navigates away must not
                        # slip through the external short-circuit.
                        if res.get("forced"):
                            results.append((label, res["forced"], res["ms"]))
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
                # A PURE external redirect (no wedge, no first-party forced layout recorded) is not
                # gated -- its reflow is not ours. A wedge on either viewport still fails, so a real
                # error is never masked by an external redirect on the sibling viewport.
                if ext and not results and not wedge:
                    print("REDIR-EXT %s" % safe_terminal(path), flush=True)
                    external.append(path)
                    continue
                offenders = any(len(forced) > budget for _vp, forced, _ms in results)
                # The mark reflects the real per-page verdict so a page counted bad never prints a
                # bare 'ok': a budget-exceeding forced layout -> FORCED, else a wedge (HTTP error /
                # lossy trace / hang on a viewport) -> WEDGE, else ok.
                mark = "FORCED" if offenders else ("WEDGE" if wedge else "ok")
                print("%-6s %s" % (mark, safe_terminal(path)), flush=True)
                for vp, forced, _ms in results:
                    if forced:
                        print("          [%s] %d forced layout(s), %.1f ms"
                              % (vp, len(forced), sum(d for _f, d in forced)), flush=True)
                        for frame, dur in forced:
                            print("            -> %6.1f ms  %s" % (dur, safe_terminal(frame)),
                                  flush=True)
                # One failing page counts ONCE (the summary is a page count): a wedge always fails; a
                # forced layout over budget fails.
                if wedge or offenders:
                    bad += 1
        finally:
            try:
                await asyncio.wait_for(browser.close(), timeout=5)
            except Exception:
                # Best-effort teardown of the shared browser at the end of the run; a close failure
                # does not change the already-computed verdict.
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


def check_roots(roots: list, settle_ms: int = 3000, budget: int = 0) -> int:
    """FAMILY entry: serve each local site checkout from a localhost mount (reusing mobile.py's
    harness, incl. SUBSITES mounting) and run the forced-reflow gate against it. SKIPs (exit 77)
    when Playwright/chromium is absent, exactly like the sibling browser lanes. Budget 0: our load
    path must force NO synchronous layout on any page (no grandfathering)."""
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
            paths = sorted(set(entry['urls']))
            rc = asyncio.run(check(base, paths, settle_ms, budget))
            if rc != 0:
                overall = 1
        finally:
            httpd.shutdown()
    return overall


def _serve_tree(tree: Path):
    """Serve a built tree on localhost via the real pre-deploy-serve.py (try_files, mirrors
    nginx/Pages), so --serve-tree needs no external server. Returns (proc, base_url).

    The CHILD binds port 0 (an OS-chosen ephemeral port) ITSELF and announces the bound port on
    stdout ('PRE_DEPLOY_SERVE_READY <port>') after binding; we read that line and measure THAT port.
    This closes the bind-then-race window a pre-picked free port had -- another local job could grab
    the port between our bind/close and the child's bind, and the gate would then measure the wrong
    server's tree. pre-deploy-serve.py ships beside this core's wiki sibling; locate it on PATH or
    via $WEBCHECK_SERVE."""
    import os
    import socket
    import threading
    serve = os.environ.get("WEBCHECK_SERVE")
    if not serve:
        from shutil import which
        serve = which("pre-deploy-serve.py")
    if not serve or not Path(serve).is_file():
        raise RuntimeError("pre-deploy-serve.py not found; set WEBCHECK_SERVE to its path")
    # Test/config seam (env, not argv): a slow CI host can need more than 10s; a test uses a short one.
    try:
        ready_timeout = float(os.environ.get("WEBCHECK_SERVE_READY_TIMEOUT", "10"))
    except ValueError:
        ready_timeout = 10.0
    proc = subprocess.Popen([sys.executable, "-Bsu", str(serve), "0", str(tree)],
                            stdout=subprocess.PIPE, text=True)
    prefix = "PRE_DEPLOY_SERVE_READY "
    result = {"port": None}
    found = threading.Event()
    # Read the child's stdout in a THREAD, not a blocking readline() on this thread: a child that
    # binds but never prints the line (a version-skewed pre-deploy-serve.py, or one logging to
    # stderr) would otherwise make readline() block forever and defeat the deadline. The thread also
    # keeps READING past the readiness line to EOF, draining stdout so later child output cannot fill
    # the ~64KB pipe buffer, block the child's write(), and wedge the server mid-run.
    def _reader():
        try:
            for line in proc.stdout:
                if result["port"] is None and line.startswith(prefix):
                    try:
                        result["port"] = int(line[len(prefix):].strip())
                    except ValueError:
                        pass
                    found.set()
        finally:
            found.set()  # unblock the waiter on EOF even if no readiness line ever arrived
    threading.Thread(target=_reader, daemon=True).start()
    if not found.wait(timeout=ready_timeout):
        proc.terminate()
        raise RuntimeError("pre-deploy-serve.py did not announce readiness within %gs" % ready_timeout)
    if result["port"] is None:  # EOF reached with no readiness line: the child exited (e.g. bind failed)
        raise RuntimeError("pre-deploy-serve.py exited before announcing its port")
    port = result["port"]
    # Trust the announced port ONLY after confirming the child actually accepts connections there: a
    # misbehaving/version-skewed server that prints a port it never bound would otherwise make the gate
    # measure whatever unrelated service already holds that port. Restores the pre-picked-port path's
    # listening-check without reintroducing its bind/close race.
    connect_deadline = time.time() + ready_timeout
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                break
        except OSError:
            if time.time() >= connect_deadline:
                proc.terminate()
                raise RuntimeError(
                    "pre-deploy-serve.py announced port %d but is not accepting connections" % port)
            time.sleep(0.05)
    return proc, "http://127.0.0.1:%d" % port


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
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--paths", nargs="*", default=None, help="explicit page paths to check")
    src.add_argument("--paths-file", type=Path, default=None, help="file: one page path per line")
    src.add_argument("--enumerate-from", type=Path, default=None,
                     help="a built tree dir: check root + every wiki/<Page>")
    return ap


def main() -> int:
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
        return asyncio.run(check(base, paths, args.settle, args.budget))
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
