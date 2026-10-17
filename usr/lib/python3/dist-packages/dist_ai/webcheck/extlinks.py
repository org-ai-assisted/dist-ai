## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""External-link reachability: every OUTBOUND http(s) link a site cites must still resolve.

Generic webcheck lane. check_site verifies INTERNAL links only (outbound are "external /
unverifiable" there); this lane fetches each distinct external URL and flags the dead ones
(DNS failure, 4xx/5xx, timeout, connection refused) -- link rot + takeover-redirect risk on
pages that cite sources and cross-link.

NETWORK + FLAKY by nature (a cited site can be transiently down or rate-limit a probe), so this
is NOT a fast per-push gate (a transient outage must not block a publish). It is a periodic / CI
check with a committed per-site baseline of ACCEPTED-unreachable URLs: only a NEWLY-dead link
(not in the baseline) fails, so known-dead or deliberately-unprobeable URLs are tolerated until
reviewed. The collection + classification logic is pure (unit-tested); only check_url touches
the network.

Line format of a baseline file: one accepted-dead URL per line (`#` comments / blanks skipped).
"""
from __future__ import annotations

import html.parser
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# Attributes whose value can be an outbound URL.
_URL_ATTRS = frozenset({"href", "src", "poster", "data"})
# Only these schemes are ever probed. urlopen would otherwise honor file:// / ftp:// / a custom
# scheme (the B310 concern: local-file read / SSRF via a crafted URL). collect_external_links
# already yields http(s) only; _probe_once re-asserts it so a non-http(s) URL can never reach
# urlopen, whatever the caller passes -- which is what makes the nosec on that urlopen honest.
_PROBE_SCHEMES = frozenset({"http", "https"})
_TIMEOUT = 10
# Pause between retries of a TRANSIENT failure (DNS / timeout / connection refused). A busy
# host (archive.org is the chronic case) refuses a burst of concurrent probes with ECONNREFUSED
# but serves fine once its throttle window clears; retrying with no gap re-hits the same window,
# so a LIVE-but-rate-limited link is misjudged "newly dead" (a flaky false red + baseline bloat).
# A short backoff lets the window clear. Only transient retries pay it; a terminal alive/dead
# verdict returns at once, and no backoff follows the final attempt.
_RETRY_BACKOFF = 1.5
# Minimum seconds between request STARTS to the SAME host, across all worker threads. check_root
# probes concurrently (8 workers) and a site cites many URLs on one host (archive.org Wayback is
# the chronic case); 8 simultaneous opens trip that host's burst throttle and all get refused,
# misjudging LIVE links dead. This spaces same-host starts so one host cannot be burst-hammered,
# while DIFFERENT hosts still run fully in parallel (the gate is periodic/CI, not a fast gate, so
# the added wall-time is acceptable). 0 disables (single-URL / test callers).
_HOST_MIN_INTERVAL = 2.0
_UA = "Mozilla/5.0 (webcheck external-link gate; +https://github.com/org-ai-assisted)"

# Social-share / intent hosts. A content page carries a share BUTTON per platform, so a site of
# N pages emits ~N near-identical permalinks per host (distinct only by the shared page's ?url=);
# on the wiki stage sites these are ~80% of ALL external links and would DOMINATE + hammer the
# platforms. A share button's "reachability" is just whether the platform is up -- NOT a cited
# resource whose rot matters -- so the wiki profile (--exclude-share-hosts) skips these hosts.
_SHARE_HOSTS = frozenset({
    "reddit.com", "www.reddit.com", "twitter.com", "x.com", "news.ycombinator.com",
    "t.me", "telegram.me", "fosstodon.org", "mastodon.social",
    "linkedin.com", "www.linkedin.com", "facebook.com", "www.facebook.com",
    "wa.me", "api.whatsapp.com", "vk.com", "xing.com",
})

_host_gate_lock = threading.Lock()
_host_next_start: Dict[str, float] = {}


def _sleep(seconds: float) -> None:
    """Backoff/throttle sleep. A module-level seam so a test can observe/suppress the delay."""
    time.sleep(seconds)


def _host_gate(host: str) -> None:
    """Block until this host's next permitted request start, reserving the slot after it. A
    RESERVATION (not a held lock): the short critical section only computes+claims the next
    start time, so concurrent same-host probes queue 1-per-interval without serializing the
    actual fetches, and other hosts are never delayed."""
    if not host or _HOST_MIN_INTERVAL <= 0:
        return
    with _host_gate_lock:
        now = time.monotonic()
        start = max(now, _host_next_start.get(host, 0.0))
        _host_next_start[host] = start + _HOST_MIN_INTERVAL
        wait = start - now
    if wait > 0:
        _sleep(wait)


class _SchemeRestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect whose target is not http(s).

    The entry guard in _probe_once only checks the INITIAL URL. urllib follows redirects, and
    its stock HTTPRedirectHandler permits an http(s) -> ftp hop -- so a cited page we probe could
    30x-redirect the opener onto ftp:// (or, on an older stdlib, another scheme) and open it,
    defeating the whole point of the http(s) allowlist. Refuse any non-web redirect target; the
    raised HTTPError is caught by _probe_once (the origin DID respond, so it reads as alive, not
    rot -- we simply decline to follow it off the web)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme.lower() not in _PROBE_SCHEMES:
            raise urllib.error.HTTPError(
                newurl, code, "redirect to non-http(s) scheme refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# A private opener so the redirect restriction applies to every probe. urlopen() uses the global
# default opener (stock redirect handler), which this must NOT mutate.
_OPENER = urllib.request.build_opener(_SchemeRestrictedRedirectHandler)


class _LinkExtractor(html.parser.HTMLParser):
    """Collect every http(s):// URL referenced by a tag attribute."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: Set[str] = set()

    def handle_starttag(self, tag, attrs) -> None:
        for name, value in attrs:
            if name in _URL_ATTRS and value:
                v = value.strip()
                if v.lower().startswith(("http://", "https://")):
                    self.urls.add(v)


def collect_external_links(root: str, exclude_hosts: Set[str] = frozenset(),
                           collapse_query: bool = False) -> Set[str]:
    """Every distinct absolute http(s) URL referenced across the site's HTML. Pure (no
    network). A fragment (`#frag`) is always stripped so the same page+fragment is probed once.

    exclude_hosts: drop any URL whose host is in this set (case-insensitive) -- used by the wiki
    profile to skip social-share/intent hosts (see _SHARE_HOSTS). collapse_query: also strip the
    `?query`, so permalink / tracking-param variants of one endpoint collapse to a single probe.
    Both default OFF, so the family lane's URL set is unchanged."""
    found: Set[str] = set()
    for base, dirs, files in os.walk(root):
        if ".git" in dirs:
            dirs.remove(".git")
        for name in files:
            if not name.lower().endswith((".html", ".htm")):
                continue
            extractor = _LinkExtractor()
            try:
                with open(os.path.join(base, name), encoding="utf-8", errors="replace") as handle:
                    extractor.feed(handle.read())
            except OSError:
                continue
            for url in extractor.urls:
                parts = urlsplit(url)
                if exclude_hosts and (parts.hostname or "").lower() in exclude_hosts:
                    continue
                parts = parts._replace(fragment="")
                if collapse_query:
                    parts = parts._replace(query="")
                found.add(parts.geturl())
    return found


def is_own_host(url: str, own_hosts: Set[str]) -> bool:
    """True when the URL points at one of the site family's OWN hosts. Those are still fetched
    (a family cross-link can rot too), but the caller may choose to treat them specially."""
    return (urlsplit(url).hostname or "").lower() in own_hosts


def _probe_once(url: str, timeout: int) -> Tuple[str, str]:
    """One HEAD-then-GET attempt -> ('alive'|'dead'|'transient', detail).

    Link ROT is the question: does the URL still point at something. A host that is UP but
    refuses the probe (401/403/429 bot-block/rate-limit) or errors (5xx) is NOT rotted -- only
    a 404/410, or a DNS / connection failure, means the resource is gone. A network-level error
    (DNS, timeout, refused) is 'transient' (retried by the caller) -- a one-off blip on a live
    host must not read as rot."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in _PROBE_SCHEMES:
        # Defensive: the collector yields http(s) only. Refuse any other scheme here so urlopen
        # below never opens file:// or a custom scheme (see _PROBE_SCHEMES).
        return "dead", "unsupported scheme (only http/https are probed)"
    host = (parts.hostname or "").lower()
    for method in ("HEAD", "GET"):
        # Gate EACH request start, not once per probe: a 403/405/501/429 on HEAD falls through
        # to GET below, and that GET is a second same-host start that must also be spaced (else
        # the HEAD->GET burst defeats the de-burst on exactly the hosts that 429 a HEAD).
        _host_gate(host)
        req = urllib.request.Request(url, method=method, headers={"User-Agent": _UA})
        try:
            # _OPENER (not urlopen) so the scheme restriction covers redirect hops too; the entry
            # guard above + the redirect handler keep every opened URL http(s), closing B310.
            with _OPENER.open(req, timeout=timeout) as resp:
                return "alive", "%s %d" % (method, resp.status)
        except urllib.error.HTTPError as exc:
            if method == "HEAD" and exc.code in (403, 405, 501, 429):
                continue   # server dislikes HEAD / bot -- try GET before judging
            if exc.code in (404, 410):
                return "dead", "HTTP %d" % exc.code
            return "alive", "HTTP %d (host up; not rot)" % exc.code
        except Exception as exc:  # noqa: BLE001
            # A link checker fetches arbitrary cited URLs: a malformed URL
            # (http.client.InvalidURL / ValueError), a server that closes mid-response
            # (http.client.BadStatusLine / IncompleteRead -- HTTPException, NOT a URLError/OSError
            # subclass), a DNS/timeout/refused (URLError/OSError), or any other fetch surprise must
            # fail THIS url as transient, never crash the worker thread + the whole gate.
            return "transient", "%s: %s" % (type(exc).__name__, exc)
    return "transient", "unreachable"


def check_url(url: str, timeout: int = _TIMEOUT, retries: int = 2,
              backoff: float = _RETRY_BACKOFF) -> Tuple[bool, str]:
    """(reachable, detail). Only a 404/410 or a persistent network failure (DNS / timeout /
    refused, after `retries`) counts as dead; a live-but-blocked/erroring host is reachable.
    Redirects are followed by urllib. A transient failure pauses `backoff` seconds before the
    next attempt (not after a terminal verdict, not after the last attempt) so a throttled-but-
    live host is not misjudged dead."""
    detail = "unreachable"
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        verdict, detail = _probe_once(url, timeout)
        if verdict == "alive":
            return True, detail
        if verdict == "dead":
            return False, detail
        if backoff > 0 and attempt + 1 < attempts:
            _sleep(backoff)
    return False, "transient after retries: %s" % detail


def parse_baseline(path: Path) -> Set[str]:
    """Accepted-unreachable URLs, one per line (`#`/blank skipped)."""
    out: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def format_baseline(urls: Set[str], site: Optional[str] = None) -> str:
    who = (" for %s" % site) if site else ""
    header = [
        "# External-link reachability: accepted-unreachable URLs%s (one per line)." % who,
        "# The gate flags only a NEWLY-dead external link; a URL listed here is tolerated",
        "# (known dead / deliberately unprobeable). Review + prune periodically.",
    ]
    return "\n".join(header + sorted(urls)) + "\n"


def _interleave_by_host(urls: Set[str]) -> List[str]:
    """Order URLs round-robin across their hosts so same-host links do not cluster. check_root
    probes with a fixed worker pool, and _host_gate makes a worker WAIT for its host's next slot;
    if consecutive URLs share a host (lexicographic order groups them), the pool fills with
    workers all sleeping on that ONE host while other hosts' URLs -- which have free slots -- sit
    queued. Spreading hosts evenly keeps the workers busy across hosts, so the one throttled host
    overlaps with the rest instead of serializing the whole run behind it."""
    from itertools import zip_longest
    buckets: Dict[str, List[str]] = {}
    for url in sorted(urls):
        buckets.setdefault((urlsplit(url).hostname or "").lower(), []).append(url)
    missing = object()
    out: List[str] = []
    for row in zip_longest(*buckets.values(), fillvalue=missing):
        out.extend(u for u in row if u is not missing)
    return out


def check_root(root: str, baseline: Set[str], timeout: int = _TIMEOUT,
               workers: int = 8, exclude_hosts: Set[str] = frozenset(),
               collapse_query: bool = False) -> Tuple[List[Tuple[str, str]], Set[str]]:
    """Fetch every external link under `root` (CONCURRENTLY -- link checking is I/O-bound and a
    site cites hundreds of URLs). Returns (new_dead, dead_all): new_dead are the (url, reason)
    NOT excused by the baseline (the gate failures); dead_all is every dead URL (for re-seeding).
    exclude_hosts / collapse_query are forwarded to collect_external_links (wiki profile)."""
    from concurrent.futures import ThreadPoolExecutor
    urls = _interleave_by_host(collect_external_links(root, exclude_hosts, collapse_query))
    new_dead: List[Tuple[str, str]] = []
    dead_all: Set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(lambda u: (u, check_url(u, timeout)), urls))
    for url, (ok, detail) in results:
        if ok:
            continue
        dead_all.add(url)
        if url not in baseline:
            new_dead.append((url, detail))
    new_dead.sort()   # stable, host-independent gate output (probe order is interleaved)
    return new_dead, dead_all


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    return baseline_dir / ("extlinks-baseline-%s.txt"
                           % os.path.basename(os.path.normpath(root)))


def _skip_77(msg: str) -> None:
    print("extlinks: SKIP (%s)" % msg, file=sys.stderr)
    raise SystemExit(77)


def main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="External-link reachability (periodic/CI).")
    ap.add_argument("--baseline-dir", required=True,
                    help="dir holding extlinks-baseline-<site>.txt")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record the current dead set as the accepted baseline instead of gating")
    ap.add_argument("--exclude-share-hosts", action="store_true",
                    help="skip social-share/intent hosts (wiki/content profile): their per-page "
                         "permalinks dominate and are not cited resources")
    ap.add_argument("--collapse-query", action="store_true",
                    help="strip the ?query before probing so permalink / tracking-param variants "
                         "of one endpoint are probed once")
    ap.add_argument("--timeout", type=int, default=_TIMEOUT)
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args(argv)
    exclude_hosts = _SHARE_HOSTS if args.exclude_share_hosts else frozenset()
    roots = [os.path.abspath(r) for r in args.roots if os.path.isdir(r)]
    if not roots:
        _skip_77("no site root found")
    baseline_dir = Path(args.baseline_dir)
    overall = 0
    for root in roots:
        bpath = _baseline_path(baseline_dir, root)
        baseline = parse_baseline(bpath) if bpath.is_file() else set()
        new_dead, dead_all = check_root(root, set() if args.write_baseline else baseline,
                                        args.timeout, exclude_hosts=exclude_hosts,
                                        collapse_query=args.collapse_query)
        name = os.path.basename(root)
        if args.write_baseline:
            baseline_dir.mkdir(parents=True, exist_ok=True)
            bpath.write_text(format_baseline(dead_all, site=name), encoding="utf-8")
            print("extlinks: seeded %d accepted-unreachable -> %s" % (len(dead_all), bpath),
                  file=sys.stderr)
            continue
        for url, detail in new_dead:
            print("%s: DEAD %s -- %s" % (name, url, detail))
        if new_dead:
            print("%s: FAIL -- %d newly-unreachable external link(s)" % (name, len(new_dead)))
            overall = 1
        else:
            print("%s: ok -- no newly-unreachable external links" % name)
    return overall


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
