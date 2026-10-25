## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""W3C Nu (vnu) HTML-conformance REGRESSION gate: baseline store + comparison, plus the
vnu.jar orchestration.

Generic webcheck lane, shared by the family Pages sites, the journal site and the wiki stage
sites. A conformance validator (unlike html-tidy, which is a linter) reports real HTML5/CSS/SVG
spec violations -- but the static sites and especially the MediaWiki-generated wiki HTML carry
pre-existing conformance debt (a stray attribute, a nesting the generator emits) not worth
blocking every publish on, while a NEW violation (a dropped closing tag, a duplicate id a new
section introduced) must fail. So the gate is REGRESSION-relative, exactly like the
axe/console/lighthouse lanes: a committed per-site baseline of ACCEPTED messages, and a fresh run
FAILS only when a conformance ERROR appears that the baseline does not already accept.

The engine below (normalize/key/parse/format/evaluate) is process-free and unit-tested
(check_vnu_test.py). The orchestration shells out to vnu (`java -jar vnu.jar`) over the built
tree -- vnu needs NO network and NO browser, so this lane runs CONFINED (sandbox-confine), unlike
the axe/lighthouse lanes which need chromium + loopback.

Violation identity: vnu reports each message with a `type` (error / info / non-document-error), a
`url` (the file), a line, and a `message` (the conformance text, e.g. 'Element "head" is missing a
required instance of child element "title"'). Only type=="error" is GATED; type=="info" (which
carries vnu's warnings) is advisory, like html-tidy warnings; type=="non-document-error" (vnu
could not check the document: an IO or schema fault) is a hard PROBLEM the caller fails on. One
(path, message) key is minted per error. The LINE is deliberately NOT part of the key: it shifts
with every unrelated edit above it, which would churn the baseline into constant false "new"s; the
message text is the stable conformance identity.

Baseline line format, one key per line:

    <path> <message>

`<path>` (a tree-relative URL path) never contains whitespace; the message (which may) is the
remainder of the line. parse_baseline is the inverse of format_baseline. vnu messages contain
typographic quotes/dashes; they are ASCII-normalized before keying so a committed baseline stays
ASCII (repo policy) and is stable regardless of vnu's rendering.

vnu itself is located via VNU_JAR (the driver sets it) + a JRE, or a `vnu` launcher on PATH. Its
absence is an env-unmet SKIP(77), like a missing chromium engine in the sibling lanes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from dist_ai.webcheck.mobile import _skip

# (tree-relative page path, ASCII-normalized conformance message).
Key = Tuple[str, str]

_CTRL_CHARS = re.compile(r'[\x00-\x1f\x7f-\x9f]')

# vnu renders element/attribute names and quotes typographically; fold the common ones to ASCII
# so a committed baseline is ASCII (repo policy) and stable, then drop any remaining non-ASCII.
_UNICODE_FOLD = {
    0x201c: '"', 0x201d: '"', 0x2018: "'", 0x2019: "'",
    0x2013: '-', 0x2014: '-', 0x2026: '...', 0x00a0: ' ',
}
_NON_ASCII = re.compile(r'[^\x20-\x7e]')


def _safe_terminal(s: str) -> str:
    """Strip C0/C1 control chars from captured text before printing it to the operator's
    terminal -- the message is page/validator-derived; mirrors webcheck.axe / webcheck.console."""
    return _CTRL_CHARS.sub('?', s)


def normalize_message(message: str) -> str:
    """Fold vnu's typographic characters to ASCII and collapse whitespace, so the key is stable
    and a committed baseline stays ASCII. A residual non-ASCII byte becomes '?' rather than
    leaking into the baseline file."""
    folded = str(message).translate(_UNICODE_FOLD)
    # Collapse whitespace (incl. the \n/\t vnu wraps long messages with) BEFORE dropping residual
    # non-ASCII -- otherwise those control bytes, being outside \x20-\x7e, turn into '?' instead
    # of folding away.
    collapsed = re.sub(r'\s+', ' ', folded).strip()
    return _NON_ASCII.sub('?', collapsed)


def _rel_path(url: str, root: str) -> str:
    """vnu's message `url` ('file:/abs/path/site/wiki/x.html') -> the tree-relative path used as
    the stable key path ('wiki/x.html'). A url outside the root (unexpected) degrades to its
    basename rather than an absolute path, so a key never embeds a machine-specific location."""
    path = url
    if path.startswith('file:'):
        path = path[len('file:'):]
    # file: URLs may carry a leading // (authority) or a single / -- normalize to an fs path.
    while path.startswith('//'):
        path = path[1:]
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return os.path.basename(path)
    if rel.startswith('..'):
        return os.path.basename(path)
    return rel


def classify(messages, root: str) -> Tuple[Set[Key], int, List[str]]:
    """Split vnu's messages into (error keys, info/advisory count, problems). Pure: the
    message -> key mapping is unit-tested without running vnu.

    - type=="error"              -> one (path, normalized-message) key (GATED).
    - type=="info"               -> advisory (counted, never gated), like html-tidy warnings.
    - type=="non-document-error" -> a PROBLEM (vnu could not check the document) the caller fails
      on -- an unauditable page is never a silent clean."""
    keys: Set[Key] = set()
    info = 0
    problems: List[str] = []
    for msg in messages or []:
        mtype = str(msg.get('type', ''))
        if mtype == 'error':
            path = _rel_path(str(msg.get('url', '')), root)
            keys.add((path, normalize_message(msg.get('message', ''))))
        elif mtype == 'info':
            info += 1
        elif mtype == 'non-document-error':
            path = _rel_path(str(msg.get('url', '')), root)
            problems.append('%s: %s' % (path, normalize_message(msg.get('message', ''))))
    return keys, info, problems


def parse_baseline(text: str) -> Set[Key]:
    """Load a committed baseline into a key set. A blank / `#` line is skipped. A line without at
    least a path and a message is a hard error (a malformed line must never read as 'no accepted
    violations', which would drop a real acceptance or fail-closed the site into noise)."""
    out: Set[Key] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            raise ValueError("expected '<path> <message>', got: %r" % line)
        out.add((parts[0], parts[1]))
    return out


def format_baseline(keys: Set[Key], site: Optional[str] = None) -> str:
    """Render a baseline file: a header, then one sorted line per accepted key. Deterministic sort
    so a re-seed diff is reviewable. parse_baseline(format_baseline(x)) == x."""
    who = (' for %s' % site) if site else ''
    header = [
        '# vnu (W3C Nu) accepted-conformance-error baseline%s. Fields: <path> <message>' % who,
        '# The gate FAILS only on a NEW error (one not listed here). A listed error is',
        '# pre-existing conformance debt we tolerate; a listed one that no longer fires is',
        '# reported as resolved, not required. Re-seed (overwrites) with:',
        '#   webcheck-vnu-sandbox --write-baseline <site-root>',
    ]
    body = [
        '%s %s' % (path, message)
        for (path, message) in sorted(keys)
    ]
    return '\n'.join(header + body) + '\n'


def evaluate(baseline_present: bool, baseline: Set[Key],
             fresh: Set[Key]) -> Tuple[int, List[Key], List[Key]]:
    """Compare a fresh error set against the accepted baseline. Pure, so the whole decision is
    unit-tested without running vnu.

    Returns (rc, new, resolved):
      - `new`      = fresh keys the baseline does not accept -> the gate FAILS on any.
      - `resolved` = baseline keys that no longer fire -> informational (a fix; never required).

    A MISSING baseline file fails CLOSED: with no committed acceptance, every fresh error is
    unaccepted and the site must be seeded first (a hollow 'no new errors' when nothing was ever
    baselined would be a fail-open). rc is 1 even when the fresh set is empty, so an unseeded site
    cannot pass by happening to be clean -- seeding is an explicit, reviewed act."""
    new = sorted(fresh - baseline)
    resolved = sorted(baseline - fresh)
    if not baseline_present:
        return 1, sorted(fresh), []
    return (1 if new else 0), new, resolved


def resolve_vnu() -> Optional[List[str]]:
    """The command that runs vnu, as an argv prefix. VNU_JAR (+ a JRE) is the sandbox driver's
    way; else a `vnu` launcher on PATH (the provisioned wrapper); else None -> an env-unmet SKIP,
    not a FAIL."""
    jar = os.environ.get('VNU_JAR')
    if jar and os.path.isfile(jar):
        java = os.environ.get('JAVA', 'java')
        return [java, '-jar', jar]
    cmd = os.environ.get('VNU_CMD', 'vnu')
    from shutil import which
    if which(cmd):
        return [cmd]
    return None


def run_vnu(vnu_cmd: List[str], root: str) -> Tuple[Set[Key], int, List[str]]:
    """Run vnu over the built tree and return (error_keys, info_count, problems). vnu writes its
    JSON report to STDERR and (with --exit-zero-always) exits 0, so the JSON -- not the exit code
    -- drives the verdict; a NON-zero exit is a real env fault (java/jar broken) and propagates.
    --skip-non-html lets vnu walk the directory itself (no argv-length limit from a huge tree)."""
    argv = vnu_cmd + ['--format', 'json', '--skip-non-html', '--exit-zero-always', root]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError('vnu exited %d (env fault, not a conformance result): %s'
                           % (proc.returncode, _safe_terminal((proc.stderr or '')[:500])))
    try:
        report = json.loads(proc.stderr or '{}')
    except json.JSONDecodeError as exc:
        raise RuntimeError('vnu did not emit parseable JSON on stderr: %s' % exc)
    return classify(report.get('messages', []), root)


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    """Per-site baseline file, keyed by the checkout's basename."""
    return baseline_dir / ('vnu-baseline-%s.txt' % os.path.basename(os.path.normpath(root)))


def check_roots(roots: List[str], baseline_dir: str) -> int:
    """Entry (run in the sandbox, confined): validate each root vs its committed accepted-error
    baseline. SKIPs(77) when vnu/JRE is absent. A missing baseline for a root fails CLOSED."""
    vnu_cmd = resolve_vnu()
    if vnu_cmd is None:
        _skip('vnu not found (set VNU_JAR + a JRE, or put a `vnu` launcher on PATH)')
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')

    overall = 0
    for root in roots:
        site = os.path.basename(os.path.normpath(root))
        fresh, info, problems = run_vnu(vnu_cmd, root)
        bpath = _baseline_path(Path(baseline_dir), root)
        present = bpath.is_file()
        baseline = parse_baseline(bpath.read_text(encoding='utf-8')) if present else set()
        rc, new, resolved = evaluate(present, baseline, fresh)
        if not present:
            print("%s: MISSING no baseline %s -- seed with "
                  "'webcheck-vnu-sandbox --write-baseline'" % (site, bpath), file=sys.stderr)
        for path, message in new:
            print('%s: NEW     %s %s' % (site, path, _safe_terminal(message[:200])),
                  file=sys.stderr)
        for path, message in resolved:
            print('%s: fixed   %s %s (baselined, no longer firing)'
                  % (site, path, _safe_terminal(message[:200])))
        for problem in problems:
            print('%s: FAIL    %s' % (site, _safe_terminal(problem)), file=sys.stderr)
        print('%s: %d accepted, %d fresh, %d NEW, %d resolved, %d info [advisory], %d problem(s)'
              % (site, len(baseline), len(fresh), len(new), len(resolved), info, len(problems)))
        if rc or problems:
            overall = 1
    return overall


def write_roots(roots: List[str], baseline_dir: str) -> int:
    """Seed (overwrite) a per-site baseline from the CURRENT error set. Refuses to seed a site
    whose pages vnu could not all check (a problem) -- a baseline seeded from a half-checked site
    would silently accept nothing for the pages that failed."""
    vnu_cmd = resolve_vnu()
    if vnu_cmd is None:
        _skip('vnu not found (set VNU_JAR + a JRE, or put a `vnu` launcher on PATH)')
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    if not roots:
        _skip('no site root found')

    for root in roots:
        site = os.path.basename(os.path.normpath(root))
        fresh, _info, problems = run_vnu(vnu_cmd, root)
        if problems:
            print('vnu: refusing to seed %s -- %d page(s) unauditable: %s'
                  % (site, len(problems), '; '.join(_safe_terminal(p) for p in problems)),
                  file=sys.stderr)
            return 2
        bpath = _baseline_path(Path(baseline_dir), root)
        Path(baseline_dir).mkdir(parents=True, exist_ok=True)
        bpath.write_text(format_baseline(fresh, site=site), encoding='utf-8')
        print('wrote %d accepted error(s) -> %s' % (len(fresh), bpath), file=sys.stderr)
    return 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description='vnu (W3C Nu) HTML-conformance regression gate.')
    ap.add_argument('--baseline-dir', required=True,
                    help='dir holding vnu-baseline-<site>.txt')
    ap.add_argument('--write-baseline', action='store_true',
                    help='seed/overwrite the baseline from the current errors instead of gating')
    ap.add_argument('roots', nargs='+', help='built site tree root(s)')
    args = ap.parse_args(argv)
    if args.write_baseline:
        return write_roots(args.roots, args.baseline_dir)
    return check_roots(args.roots, args.baseline_dir)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
