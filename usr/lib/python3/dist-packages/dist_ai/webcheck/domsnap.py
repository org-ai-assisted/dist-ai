## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""DOM / visual-regression snapshot: the single front door for BOTH the static Pages sites and
the live MediaWiki.

The capture/normalize/diff engine ships in ENGINE_DIR (usr/share/domsnap-engine/
{snapshot,normalize,diff}.py); diff.py is the shared comparison engine (DOM-text + asset-manifest +
computed-styles + console + errors + pHash screenshot, PHASH_THRESHOLD=3), wiki-agnostic.

  - GENERIC static lane (capture / diff-baseline / promote): the 5 hand-written family Pages trees,
    captured IN-PROCESS by the thin generic capture + normalizer below (no MediaWiki login/api/title
    machinery -- plain path navigation; the normalizer only collapses the per-run mount host:port so
    a baseline is port-stable), via two front doors (a local directory served through
    webcheck.mobile's _MountHandler, or a served --base URL), over a committed REPRESENTATIVE page
    list. Baselines + the raw/normalized corpora live under ~/private-cache/webcheck-domsnap/ (NOT
    committed: screenshots + asset bodies are large + regenerable, and pushing them risks a repo-abuse
    ban). Local / on-demand, run via webcheck-domsnap-sandbox.
  - WIKI lane (wiki-capture / wiki-normalise / wiki-run / wiki-diff / wiki-diff-baseline /
    wiki-promote): the live MediaWiki, driven by ENGINE_DIR/{snapshot,normalize,diff}.py (which carry
    the MediaWiki login/api/intent + RLCONF/ResourceLoader/skin-selector scrubs) as a subprocess,
    configured through the environment (see _wiki_env: BASE_URL/PAGES_FILE/RAW_DIR/FIX_DIR/
    BASELINE_DIR/CAPTURE_MODES/BROWSERS/LOCALES/WIKI_USER/ADMIN_USER/POSTEDIT_PAGES/...).

Playwright is imported only inside capture(), so this module imports (and its canary runs)
browser-free.
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import hashlib
import json
import mimetypes
import os
import re
import shutil
import subprocess  # nosec B404 -- invokes the fixed diff.py with our own paths, no shell
import sys
import threading
import urllib.parse
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from dist_ai.webcheck import mobile

CACHE_ROOT = Path(os.environ.get(
    "WEBCHECK_DOMSNAP_CACHE", os.path.expanduser("~/private-cache/webcheck-domsnap")))
# The capture/normalize/diff engine ships in one dir: the static lane reuses diff.py as a
# subprocess, and the wiki-* subcommands drive all three. Overridable so a checkout / the review
# sandbox can point elsewhere.
ENGINE_DIR = os.environ.get("WEBCHECK_DOMSNAP_ENGINE", "/usr/share/domsnap-engine")
DIFF_PY = os.environ.get("WEBCHECK_DOMSNAP_DIFF", os.path.join(ENGINE_DIR, "diff.py"))
SNAPSHOT_PY = os.path.join(ENGINE_DIR, "snapshot.py")
NORMALIZE_PY = os.path.join(ENGINE_DIR, "normalize.py")
# Host:port a local mount is served on is per-run volatile; collapse it to this stable token so a
# baseline captured on one port matches a candidate captured on another.
HOST_PLACEHOLDER = "http://site.local"

# Per-request / per-run volatile response headers: drop them from the manifest so a re-capture
# does not diff on the clock or a cache token. (Generic subset of mediawiki normalize.py's set.)
VOLATILE_HEADERS = frozenset({
    "date", "age", "etag", "last-modified", "expires", "set-cookie", "vary", "keep-alive",
    "connection", "x-request-id", "x-cache", "x-served-by", "cf-ray", "report-to", "nel",
})

# Generic structural selectors for the computed-style axis -- the family design-system hooks plus
# ordinary semantic elements. A CSS regression invisible to the HTML diff (cascade/specificity)
# surfaces here. (NOT the MediaWiki selector set; that is the deferred wiki profile.)
COMPUTED_STYLE_SELECTORS = [
    "html", "body", "header", "footer", "main", "nav",
    "h1", "h2", "h3", "a", "pre", "code", "button",
    ".wrap", ".term", ".brand", ".status", ".menubtn",
]
COMPUTED_STYLE_PROPS = [
    "display", "position", "color", "background-color", "font-size", "font-family",
    "font-weight", "margin", "padding", "border", "width", "max-width", "visibility",
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ext_for(content_type: str, url: str) -> str:
    """Pick a stable extension for a content-addressed asset body (generic; from snapshot.py)."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    exact = {
        "text/html": ".html", "text/css": ".css", "application/javascript": ".js",
        "text/javascript": ".js", "application/json": ".json", "image/png": ".png",
        "image/jpeg": ".jpg", "image/svg+xml": ".svg", "image/webp": ".webp",
        "image/gif": ".gif", "image/x-icon": ".ico", "font/woff": ".woff",
        "font/woff2": ".woff2", "text/plain": ".txt",
    }
    if ct in exact:
        return exact[ct]
    guess = mimetypes.guess_extension(ct) if ct else None
    if guess:
        return guess
    suffix = Path(url.split("?", 1)[0]).suffix.lower()
    return suffix if suffix and len(suffix) <= 6 else ".bin"


def page_slug(path: str) -> str:
    """Directory name for a page path: '/' -> 'index', else path with separators flattened."""
    p = path.strip("/")
    if not p:
        return "index"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", p)
    # A component of "." / ".." (or any leading-dot run) would resolve OUTSIDE the site dir;
    # neutralise the leading dots so a slug is always a plain child name under the site raw dir.
    return re.sub(r"^\.+", lambda m: "_" * len(m.group(0)), slug)


def load_pages(conf: Path) -> List[str]:
    """One page path per line; '#'/blank skipped. '/' means the site root."""
    out: List[str] = []
    for raw in conf.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _unique_slugs(pages: List[str]) -> None:
    """Fail loud if two distinct page paths collapse to the same slug: the later capture would
    overwrite the earlier, silently hiding a regression on the shadowed page."""
    seen: Dict[str, str] = {}
    for path in pages:
        slug = page_slug(path)
        if slug in seen:
            raise SystemExit("domsnap: pages %r and %r both map to slug %r"
                             % (seen[slug], path, slug))
        seen[slug] = path


def _ignore_tls(base: str) -> bool:
    """Whether to accept an invalid TLS cert during capture. True only for a NON-https base (the
    loopback http mount front door) or an explicit WEBCHECK_DOMSNAP_INSECURE_TLS=1 opt-in for a
    known self-signed stage -- never silently for an https base, or a MITM'd page would be
    captured, normalised and promoted as the trusted baseline."""
    if os.environ.get("WEBCHECK_DOMSNAP_INSECURE_TLS", "") == "1":
        return True
    return urllib.parse.urlsplit(base).scheme != "https"


# ---- capture (Playwright; the only part that needs a browser) --------------------------------

def _record_response_factory(page_dir: Path, manifest: dict):
    assets_dir = page_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)

    async def on_response(response):
        url = response.url
        if url in manifest:
            return
        try:
            body = await response.body()
        except Exception as exc:  # noqa: BLE001 -- a body can be unavailable (redirect, aborted)
            manifest[url] = {"error": "body unavailable: %s" % exc}
            return
        digest = sha256_hex(body)
        headers = {k.lower(): v for k, v in response.headers.items()}
        ct = headers.get("content-type", "")
        asset_path = assets_dir / (digest + ext_for(ct, url))
        if not asset_path.exists():
            asset_path.write_bytes(body)
        manifest[url] = {"sha256": digest, "size": len(body), "content_type": ct,
                         "status": response.status, "asset": asset_path.name, "headers": headers}

    return on_response


async def _capture_one(context, base: str, path: str, viewport: dict, scheme: str,
                       out_dir: Path, timeout_ms: int) -> Tuple[str, int]:
    page = await context.new_page()
    await page.set_viewport_size(viewport)
    await page.emulate_media(color_scheme=scheme)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    console_events: List[dict] = []
    request_failures: List[dict] = []
    pending: List = []
    recorder = _record_response_factory(out_dir, manifest)   # one recorder per page
    page.on("response", lambda r: pending.append(asyncio.ensure_future(recorder(r))))
    page.on("console", lambda m: console_events.append({"type": m.type, "text": m.text}))
    page.on("pageerror", lambda e: console_events.append({"type": "pageerror", "text": str(e)}))
    page.on("requestfailed", lambda r: request_failures.append(
        {"url": r.url, "failure": (r.failure or "")}))

    url = base.rstrip("/") + "/" + path.lstrip("/") if path != "/" else base
    status = 0
    try:
        resp = await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        status = resp.status if resp else 0
    except Exception as exc:  # noqa: BLE001 -- a navigation can time out; record what we have
        console_events.append({"type": "pageerror", "text": "navigation: %s" % exc})
    await page.wait_for_timeout(300)
    # Drain in-flight response recorders before snapshotting the manifest.
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    (out_dir / "dom.html").write_text(await page.content(), encoding="utf-8")
    await page.screenshot(path=str(out_dir / "screenshot.png"), full_page=False, animations="disabled")
    cstyles = await page.evaluate(
        """([sels, props]) => { const o={}; for (const s of sels) { let el; try { el=document.querySelector(s); }
           catch(_){ el=null; } if(!el){ o[s]=null; continue; } const cs=getComputedStyle(el); const r={};
           for (const p of props) r[p]=cs.getPropertyValue(p); o[s]=r; } return o; }""",
        [COMPUTED_STYLE_SELECTORS, COMPUTED_STYLE_PROPS])
    (out_dir / "computed_styles.json").write_text(json.dumps(cstyles, indent=2, sort_keys=True),
                                                  encoding="utf-8")
    (out_dir / "console.json").write_text(json.dumps(console_events, indent=2, sort_keys=True),
                                          encoding="utf-8")
    (out_dir / "manifest.json").write_text(
        json.dumps(dict(sorted(manifest.items())), indent=2, sort_keys=True), encoding="utf-8")
    http_errors = [{"url": u, "status": e["status"]} for u, e in manifest.items()
                   if isinstance(e.get("status"), int) and e["status"] >= 400]
    errors = {"http_errors": sorted(http_errors, key=lambda x: (x["status"], x["url"])),
              "request_failures": sorted(request_failures, key=lambda x: x["url"]),
              "console_errors": [e for e in console_events
                                 if e.get("type") in ("error", "warning", "pageerror")]}
    (out_dir / "errors.json").write_text(json.dumps(errors, indent=2, sort_keys=True),
                                         encoding="utf-8")
    await page.close()
    return path, status


async def _capture_all(base: str, pages: List[str], modes: List[Tuple[dict, str, str]],
                       site_raw: Path, timeout_ms: int) -> int:
    from playwright.async_api import async_playwright
    ignore_tls = _ignore_tls(base)
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            for path in pages:
                slug = page_slug(path)
                for viewport, scheme, mode_name in modes:
                    context = await browser.new_context(ignore_https_errors=ignore_tls,
                                                        java_script_enabled=True)
                    try:
                        out_dir = site_raw / slug / mode_name
                        await _capture_one(context, base, path, viewport, scheme, out_dir, timeout_ms)
                    finally:
                        await context.close()
        finally:
            await browser.close()
    return 0


def _modes() -> List[Tuple[dict, str, str]]:
    """Representative capture modes. Default a single deterministic desktop-light mode; set
    WEBCHECK_DOMSNAP_MODES=desktop-light,mobile-dark,... to widen."""
    catalog = {
        "desktop-light": ({"width": 1280, "height": 800}, "light"),
        "desktop-dark": ({"width": 1280, "height": 800}, "dark"),
        "mobile-light": ({"width": 390, "height": 844}, "light"),
        "mobile-dark": ({"width": 390, "height": 844}, "dark"),
    }
    want = os.environ.get("WEBCHECK_DOMSNAP_MODES", "desktop-light").split(",")
    out = []
    for name in [w.strip() for w in want if w.strip()]:
        if name not in catalog:
            raise SystemExit("domsnap: unknown mode %r (known: %s)" % (name, ", ".join(catalog)))
        vp, scheme = catalog[name]
        out.append((vp, scheme, name))
    return out


# ---- serve a local tree (family front door; reuses webcheck.mobile) --------------------------

def _serve(docroot: str):
    """Start a localhost static server for `docroot`; return (base_url, shutdown-callable)."""
    handler = functools.partial(mobile._MountHandler, directory=docroot)
    httpd = mobile._MountingTCPServer(("127.0.0.1", 0), handler)
    httpd.mounts = {}
    httpd.daemon_threads = True
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def shutdown():
        httpd.shutdown()
        httpd.server_close()

    return "http://127.0.0.1:%d" % port, shutdown


# ---- normalize (generic: collapse the per-run mount host:port) -------------------------------

def _scrub(text: str, base_url: str) -> str:
    """Collapse the per-run mount base URL to HOST_PLACEHOLDER in BOTH plain and percent-encoded
    forms. share.js (and friends) write encodeURIComponent(location.href) into link hrefs, so the
    encoded `http%3A%2F%2F127.0.0.1%3A<port>` must be scrubbed too or the random port diffs.
    Both matches are ANCHORED with a no-trailing-digit lookahead so our port is not matched inside
    a longer one that merely starts with it (`:38271` within `:382719`), and the encoded form is
    matched case-insensitively so a lower-cased `%3a` collapses like encodeURIComponent's `%3A`."""
    enc_base = urllib.parse.quote(base_url, safe="")
    enc_ph = urllib.parse.quote(HOST_PLACEHOLDER, safe="")
    text = re.sub(re.escape(base_url) + r"(?![0-9])", HOST_PLACEHOLDER, text)
    text = re.sub(re.escape(enc_base) + r"(?![0-9])", enc_ph, text, flags=re.IGNORECASE)
    return text


def normalize_dir(raw_site: Path, fix_site: Path, base_url: str) -> None:
    """Copy raw_site -> fix_site, rewriting the per-run base URL (host:port) to HOST_PLACEHOLDER
    in dom.html, manifest.json keys/values and errors.json, so a baseline captured on one port
    matches a candidate on another. The screenshot + asset bodies carry no host, copied as-is.
    (The MediaWiki RLCONF/ResourceLoader/skin scrubs are the deferred wiki profile.)"""
    if fix_site.exists():
        shutil.rmtree(fix_site)
    for page_dir in sorted(p for p in raw_site.iterdir() if p.is_dir()):
        for mode_dir in sorted(p for p in page_dir.iterdir() if p.is_dir()):
            dst = fix_site / page_dir.name / mode_dir.name
            dst.mkdir(parents=True, exist_ok=True)
            for item in mode_dir.iterdir():
                if item.name == "manifest.json":
                    (dst / item.name).write_text(
                        _normalize_manifest(item.read_text(encoding="utf-8"), base_url),
                        encoding="utf-8")
                elif item.name in ("dom.html", "console.json", "errors.json", "computed_styles.json"):
                    (dst / item.name).write_text(
                        _scrub(item.read_text(encoding="utf-8"), base_url), encoding="utf-8")
                elif item.is_dir():
                    shutil.copytree(item, dst / item.name)
                else:
                    shutil.copy2(item, dst / item.name)


def _normalize_manifest(text: str, base_url: str) -> str:
    """Collapse the per-run host:port in URL keys, and drop volatile response headers (the clock /
    cache tokens), so a re-capture does not diff on either. Keys are re-sorted for stability."""
    data = json.loads(text)
    out: dict = {}
    for url, entry in data.items():
        key = _scrub(url, base_url)
        if isinstance(entry, dict):
            entry = dict(entry)
            hdrs = entry.get("headers")
            if isinstance(hdrs, dict):
                # Drop volatile headers, and scrub the per-run host:port out of the SURVIVING
                # header VALUES: a Location / Link / Access-Control-Allow-Origin header can echo
                # the mount origin+port, which would otherwise diff on the random port.
                entry["headers"] = {k: (_scrub(v, base_url) if isinstance(v, str) else v)
                                    for k, v in hdrs.items() if k.lower() not in VOLATILE_HEADERS}
            if isinstance(entry.get("error"), str):
                entry["error"] = _scrub(entry["error"], base_url)
        out[key] = entry
    return json.dumps(dict(sorted(out.items())), indent=2, sort_keys=True)


# ---- CLI -------------------------------------------------------------------------------------

def _safe_component(name: str, what: str) -> str:
    """A cache-subtree name (--site label, a baseline/fixtures tag) must be ONE path component --
    never '.'/'..' nor contain a separator -- so an interpolated value cannot escape its cache root
    and have rmtree / copytree act on an arbitrary directory. Fails loud on anything unsafe."""
    if (not name) or name in (".", "..") or "/" in name or os.sep in name or "\x00" in name:
        raise SystemExit("domsnap: unsafe %s %r (must be a single path component)" % (what, name))
    return name


def _site_dirs(site: str) -> Tuple[Path, Path, Path]:
    _safe_component(site, "--site")
    return (CACHE_ROOT / "raw" / site, CACHE_ROOT / "fixtures" / site,
            CACHE_ROOT / "baseline" / site)


def _resolve_base(args) -> Tuple[str, Optional[Callable[[], None]]]:
    """Return (base_url, shutdown-or-None). --root serves a local tree; --base uses a served URL."""
    if args.root:
        root = os.path.abspath(args.root)
        if not os.path.isfile(os.path.join(root, "index.html")):
            raise SystemExit("domsnap: --root %s is not a site root (no index.html)" % root)
        return _serve(root)
    return args.base.rstrip("/"), None


def _cmd_capture(args) -> int:
    pages = load_pages(Path(args.pages))
    modes = _modes()
    # Fail loud BEFORE the destructive rmtree below: an empty page list or an empty mode list
    # would wipe the previous capture and then crash in normalize_dir on an absent raw dir (an
    # opaque state), instead of reporting the misconfiguration.
    if not pages:
        raise SystemExit("domsnap: no pages in %s" % args.pages)
    if not modes:
        raise SystemExit("domsnap: no capture modes (WEBCHECK_DOMSNAP_MODES is empty)")
    _unique_slugs(pages)
    raw, _fix, _base = _site_dirs(args.site)
    if raw.exists():
        shutil.rmtree(raw)
    base_url, shutdown = _resolve_base(args)
    try:
        asyncio.run(_capture_all(base_url, pages, modes, raw, args.timeout))
    finally:
        if shutdown:
            shutdown()
    # Normalise straight away against the base URL used for this capture.
    normalize_dir(raw, _fix, base_url)
    print("domsnap: captured + normalised %d page(s) -> %s" % (len(pages), _fix), file=sys.stderr)
    return 0


def _cmd_diff_baseline(args) -> int:
    _raw, fix, baseline = _site_dirs(args.site)
    if not baseline.is_dir():
        print("domsnap: no baseline for %s at %s -- run 'promote' first" % (args.site, baseline),
              file=sys.stderr)
        return 1
    if not fix.is_dir():
        print("domsnap: no current fixtures for %s -- run 'capture' first" % args.site,
              file=sys.stderr)
        return 1
    # Reuse diff.py VERBATIM as the comparison engine.
    proc = subprocess.run(  # nosec B603 -- fixed interpreter + our own diff.py + our dirs
        [sys.executable, DIFF_PY, str(baseline), str(fix)])
    return proc.returncode


def _git_commit_baseline(site: str) -> None:
    """Version the promoted baseline in a LOCAL git repo at CACHE_ROOT (no remote -- the
    raw/fixtures corpora are .gitignored), so a promotion is git-diffable (text axes diff;
    screenshots show as binary-changed) for review. No remote is ever added, so the git push
    guard has nothing to push: the large corpus never reaches a hosting service (abuse-ban risk).
    Best-effort: a git failure must not fail the promote itself."""
    repo = str(CACHE_ROOT)
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "webcheck-domsnap", "GIT_AUTHOR_EMAIL": "noreply@localhost",
           "GIT_COMMITTER_NAME": "webcheck-domsnap", "GIT_COMMITTER_EMAIL": "noreply@localhost"}
    try:
        if not (CACHE_ROOT / ".git").is_dir():
            subprocess.run(["git", "-C", repo, "init", "-q"], check=True, env=env)  # nosec B603/B607
            (CACHE_ROOT / ".gitignore").write_text("raw/\nfixtures/\n", encoding="utf-8")
        subprocess.run(["git", "-C", repo, "add", ".gitignore", "baseline/" + site],
                       check=True, env=env)  # nosec B603 B607
        staged = subprocess.run(["git", "-C", repo, "diff", "--cached", "--quiet"], env=env)
        if staged.returncode != 0:  # something changed -> record the promotion
            subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "domsnap: promote " + site],
                           check=True, env=env)  # nosec B603 B607
    except Exception as exc:  # noqa: BLE001 -- versioning is a review convenience, not the gate
        print("domsnap: baseline committed to files but git versioning skipped: %s" % exc,
              file=sys.stderr)


def _cmd_promote(args) -> int:
    _raw, fix, baseline = _site_dirs(args.site)
    if not fix.is_dir():
        print("domsnap: no fixtures to promote for %s -- run 'capture' first" % args.site,
              file=sys.stderr)
        return 1
    if baseline.exists():
        shutil.rmtree(baseline)
    baseline.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fix, baseline)
    _git_commit_baseline(args.site)
    print("domsnap: promoted %s fixtures -> baseline %s" % (args.site, baseline), file=sys.stderr)
    return 0


# ---- wiki lane (the live MediaWiki, via the ENGINE_DIR scripts as a subprocess) --------------

def _wiki_env() -> Dict[str, str]:
    """Environment defaults for the wiki engine, each still overridable by the matching env var.
    snapshot.py / normalize.py read these; FIX_DIR / BASELINE_DIR name the normalised + baseline
    corpora the diff/promote subcommands below operate on."""
    env = dict(os.environ)
    env.setdefault("PAGES_FILE", os.path.join(ENGINE_DIR, "wiki-pages.conf"))
    env.setdefault("BASE_URL", "https://www.kicksecure.com")
    env.setdefault("TIMEOUT_MS", "30000")
    cache = os.path.expanduser("~/private-cache/domsnap-wiki")
    env.setdefault("RAW_DIR", os.path.join(cache, "raw"))
    env.setdefault("FIX_DIR", os.path.join(cache, "fixtures"))
    env.setdefault("BASELINE_DIR", os.path.join(cache, "baseline"))
    return env


def _cmd_wiki_capture(args) -> int:
    env = _wiki_env()
    # Scope the capture under a run TAG (RAW_DIR/<tag>) so the same tag names the fixture the
    # diff/promote subcommands read -- the whole sequence (capture -> normalise -> diff-baseline /
    # promote) keys off ONE tag instead of writing to a top-level dir the tagged reads miss.
    raw_dir = os.path.join(env["RAW_DIR"], _safe_component(args.tag, "tag"))
    env["RAW_DIR"] = raw_dir
    os.makedirs(raw_dir, exist_ok=True)
    # snapshot.py reads BASE_URL / RAW_DIR / PAGES_FILE / CAPTURE_MODES / WIKI_USER / ... from env.
    return subprocess.run([sys.executable, SNAPSHOT_PY], env=env).returncode  # nosec B603


def _cmd_wiki_normalise(args) -> int:
    env = _wiki_env()
    tag = _safe_component(args.tag, "tag")
    raw = Path(env["RAW_DIR"]) / tag
    fix = Path(env["FIX_DIR"]) / tag
    fix.mkdir(parents=True, exist_ok=True)
    page_dirs = sorted(p for p in raw.iterdir() if p.is_dir()) if raw.is_dir() else []
    if not page_dirs:
        print("domsnap wiki-normalise: no raw page dirs under %s -- run 'wiki-capture %s' first"
              % (raw, tag), file=sys.stderr)
        return 1
    # Per-page dirs are independent; normalise them in parallel (NORMALISE_JOBS, default 8), each
    # via normalize.py <raw/page> <fix/page>, as the old wrapper's xargs -P did.
    jobs = max(1, int(os.environ.get("NORMALISE_JOBS", "8")))

    def one(page_dir: Path) -> int:
        return subprocess.run(  # nosec B603
            [sys.executable, NORMALIZE_PY, str(page_dir), str(fix / page_dir.name)], env=env
        ).returncode

    from concurrent.futures import ThreadPoolExecutor
    rc = 0
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for r in ex.map(one, page_dirs):
            rc = rc or r
    return rc


def _cmd_wiki_run(args) -> int:
    # capture THEN normalise, in order (normalise only if capture succeeded).
    rc = _cmd_wiki_capture(args)
    return rc if rc else _cmd_wiki_normalise(args)


def _cmd_wiki_diff(args) -> int:
    env = _wiki_env()
    fix = Path(env["FIX_DIR"])
    cmd = [sys.executable, DIFF_PY,
           str(fix / _safe_component(args.a, "diff tag")),
           str(fix / _safe_component(args.b, "diff tag"))]
    if args.brief:
        cmd.append("--brief")
    return subprocess.run(cmd, env=env).returncode  # nosec B603


def _cmd_wiki_diff_baseline(args) -> int:
    env = _wiki_env()
    fix = Path(env["FIX_DIR"])
    baseline = Path(env["BASELINE_DIR"])
    cmd = [sys.executable, DIFF_PY, str(baseline), str(fix / _safe_component(args.tag, "tag"))]
    if args.brief:
        cmd.append("--brief")
    return subprocess.run(cmd, env=env).returncode  # nosec B603


def _cmd_wiki_promote(args) -> int:
    env = _wiki_env()
    fix = Path(env["FIX_DIR"])
    baseline = Path(env["BASELINE_DIR"])
    src = fix / _safe_component(args.tag, "tag")
    if not src.is_dir():
        print("domsnap wiki-promote: missing %s -- run wiki-capture/normalise first" % src,
              file=sys.stderr)
        return 1
    if baseline.exists():
        shutil.rmtree(baseline)
    baseline.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, baseline)
    print("domsnap wiki-promote: promoted %s -> %s" % (src, baseline), file=sys.stderr)
    return 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Generic DOM/visual-regression snapshot lane.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture", help="capture + normalise a site's representative pages")
    src = cap.add_mutually_exclusive_group(required=True)
    src.add_argument("--root", help="serve this local site tree (family front door)")
    src.add_argument("--base", help="capture against this served base URL (stage front door)")
    cap.add_argument("--site", required=True, help="site label (names the cache subtree)")
    cap.add_argument("--pages", required=True, help="representative page list (one path per line)")
    cap.add_argument("--timeout", type=int, default=30000, help="per-page timeout (ms)")
    cap.set_defaults(fn=_cmd_capture)
    dfb = sub.add_parser("diff-baseline", help="diff current fixtures against the promoted baseline")
    dfb.add_argument("--site", required=True)
    dfb.set_defaults(fn=_cmd_diff_baseline)
    pro = sub.add_parser("promote", help="promote current fixtures to the baseline")
    pro.add_argument("--site", required=True)
    pro.set_defaults(fn=_cmd_promote)

    # Wiki lane: the relocated MediaWiki engine, configured entirely through the environment (see
    # _wiki_env + the engine docstrings: BASE_URL/PAGES_FILE/RAW_DIR/FIX_DIR/BASELINE_DIR/
    # CAPTURE_MODES/BROWSERS/LOCALES/WIKI_USER/ADMIN_USER/POSTEDIT_PAGES/...).
    # capture/normalise/run take a run TAG: raw -> RAW_DIR/<tag>, fixtures -> FIX_DIR/<tag>, so the
    # same tag is what wiki-diff / wiki-diff-baseline / wiki-promote read.
    wca = sub.add_parser("wiki-capture", help="capture the live wiki into fixture tag (engine snapshot.py)")
    wca.add_argument("tag")
    wca.set_defaults(fn=_cmd_wiki_capture)
    wno = sub.add_parser("wiki-normalise", help="normalise a tag's raw captures -> fixtures")
    wno.add_argument("tag")
    wno.set_defaults(fn=_cmd_wiki_normalise)
    wru = sub.add_parser("wiki-run", help="wiki-capture then wiki-normalise for a tag")
    wru.add_argument("tag")
    wru.set_defaults(fn=_cmd_wiki_run)
    wdf = sub.add_parser("wiki-diff", help="diff two wiki fixture tags")
    wdf.add_argument("a")
    wdf.add_argument("b")
    wdf.add_argument("--brief", action="store_true", help="suppress the per-asset body diff")
    wdf.set_defaults(fn=_cmd_wiki_diff)
    wdb = sub.add_parser("wiki-diff-baseline", help="diff the wiki baseline against a fixture tag")
    wdb.add_argument("tag")
    wdb.add_argument("--brief", action="store_true", help="suppress the per-asset body diff")
    wdb.set_defaults(fn=_cmd_wiki_diff_baseline)
    wpr = sub.add_parser("wiki-promote", help="promote a wiki fixture tag to the baseline")
    wpr.add_argument("tag")
    wpr.set_defaults(fn=_cmd_wiki_promote)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
