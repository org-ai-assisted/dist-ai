## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Spell-check of the BUILT site tree: flag misspellings in the emitted HTML prose.

Delegates to `cspell` (offline, read-only) over the built `*.html`, with a committed project
dictionary of domain terms (Whonix, Kicksecure, Tor, sdwdate, ...) so technical content does not
flood false positives, and gates on a per-site accepted baseline so a reviewed residual (a proper
noun, a deliberate string) does not re-fail -- the same shape as the secrets + extlinks lanes.

cspell is npm-only (not Debian), so this core runs INSIDE the review sandbox, driven by
webcheck-cspell-sandbox. cspell is ASSUMED present there and called directly; its absence is an
ENVIRONMENT BUG that FAILS LOUD (exit 1), never a SKIP -- a spell-check that silently did not run
is the false green this gate exists to prevent. Pure parsing + baseline; only `_run_cspell`
shells out.
"""
from __future__ import annotations

import os
import re
import subprocess  # nosec B404 -- invokes the fixed cspell binary, no shell, no user input in argv
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple

# cspell's per-issue line: "<file>:<line>:<col> - Unknown word (<word>) fix: (<suggestion>)".
# Capture the file and the flagged word; the suggestion/position are forensic-only.
_ISSUE_RE = re.compile(r"^(?P<file>.+?):\d+:\d+ - (?:Unknown|Forbidden) word \((?P<word>[^)]+)\)")


def _run_cspell(root: str, config: str) -> List[Tuple[str, str]]:
    """Run cspell over `root`'s HTML and return [(root-relative file, word-lowercased), ...].

    cspell is a hard dependency in the sandbox, so it is called directly (no has-X preflight). A
    missing binary surfaces as FileNotFoundError; a scan ERROR (any exit other than 0=clean /
    1=issues-found, or an unsupported-engine line) raises RuntimeError. main() turns either into a
    loud exit-1 FAILURE, never a skip: a scan error must NEVER read as 'clean'."""
    # cwd=root + a RELATIVE glob so cspell's default --root is `root`: an ABSOLUTE glob embeds
    # root's basename, where a glob metachar ('[' etc.) would silently match nothing, and a root
    # OUTSIDE the process cwd is filtered out entirely -> cspell checks 0 files and exits 0 (a
    # false clean). The config is abspath'd first (cwd changes under it); its relative dictionary
    # paths resolve against the config file's own location, not cwd.
    # Accepted limitation: an in-document `cspell:disable` directive in the CHECKED HTML would
    # suppress spell-check to EOF. The input is our own curated/built Pages HTML, which carries no
    # cspell directives, so this is not a realistic bypass; revisit if that content ever does.
    # NO --no-must-find-files on purpose: if the glob matches 0 files (an empty tree, or a site
    # whose only index.html is a SYMLINK -- cspell's glob has followSymbolicLinks:false, so it is
    # skipped), cspell exits non-zero and this raises below, failing LOUD rather than a false green.
    proc = subprocess.run(  # nosec B603 -- fixed argv, no shell=True, paths are ours
        ["cspell", "lint", "--no-progress", "--no-color", "--no-summary",
         "--config", os.path.abspath(config),
         "--", os.path.join("**", "*.html")],
        capture_output=True, text=True, cwd=root)
    stderr = proc.stderr or ""
    # cspell: 0 = clean, 1 = issues found. Anything else is a real error (bad config, unreadable
    # tree, an unsupported-engine refusal) -> fail loud, never the false-clean this gate prevents.
    if proc.returncode not in (0, 1) or "Unsupported" in stderr:
        raise RuntimeError("cspell errored (rc=%d): %s"
                           % (proc.returncode, (stderr or proc.stdout or "")[-300:]))
    out: List[Tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        m = _ISSUE_RE.match(line.strip())
        if not m:
            continue
        fp = m.group("file")
        rel = os.path.relpath(fp if os.path.isabs(fp) else os.path.join(root, fp), root)
        out.append((rel, m.group("word").lower()))
    # cspell exits 1 for BOTH issues-found AND a real error (a missing/invalid config or
    # dictionary writes the error to stderr with NO issue on stdout). rc==1 with NO parseable
    # issue is therefore an ERROR, never clean -- fail loud (the silent pass this gate prevents),
    # mirroring the gitleaks lane's "rc 1 with an empty report" check.
    if proc.returncode == 1 and not out:
        raise RuntimeError("cspell exit 1 with no parseable issues (config/dictionary error, or 0 "
                           "files matched?): %s" % ((stderr or proc.stdout or "")[-300:]))
    return out


def finding_key(rel_file: str, word: str) -> str:
    """Checkout-INDEPENDENT baseline key `<root-relative file>:<word-lowercased>`. Line/column
    are excluded on purpose, so an accepted word survives the prose moving around the file."""
    return "%s:%s" % (rel_file, word)


def scan_root(root: str, config: str, baseline: Set[str]) -> Tuple[List[str], Set[str]]:
    """(new_findings, all_keys): new_findings are the keys NOT in `baseline` (the gate failures);
    all_keys is every finding's key (for re-seeding a baseline)."""
    new: Set[str] = set()      # dedup: cspell emits one line per OCCURRENCE; a word appearing N
    all_keys: Set[str] = set() # times in a file is ONE key, not N (no inflated count / repeats)
    for rel, word in _run_cspell(root, config):
        key = finding_key(rel, word)
        all_keys.add(key)
        if key not in baseline:
            new.add(key)
    return sorted(new), all_keys


def parse_baseline(path: Path) -> Set[str]:
    out: Set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def format_baseline(keys: Set[str], site: Optional[str] = None) -> str:
    who = (" for %s" % site) if site else ""
    header = [
        "# Spell-check: accepted finding keys%s, one per line: <relative file>:<word>." % who,
        "# A key listed here is tolerated (a proper noun, a deliberate string, a term not worth",
        "# adding to the shared project dictionary). The gate flags only a NEWLY-unknown word.",
        "# A word for EVERY site belongs in cspell-assets/project-dictionary.txt instead. Prune",
        "# when the prose changes.",
    ]
    return "\n".join(header + sorted(keys)) + "\n"


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    from dist_ai.webcheck import cli
    return baseline_dir / ("cspell-baseline-%s.txt" % cli.site_name(root))


def main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Spell-check the built site tree (cspell).")
    ap.add_argument("--baseline-dir", required=True,
                    help="dir holding cspell-baseline-<site>.txt")
    ap.add_argument("--config", default="cspell-assets/cspell.json",
                    help="cspell config (with the project dictionary); relative to cwd by default")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record the current findings as the accepted baseline instead of gating")
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args(argv)
    from dist_ai.webcheck import cli
    # A named root that does not resolve FAILS loud (not a silent drop / skip). nargs="+"
    # guarantees at least one named root, so there is no genuinely-empty case to skip.
    roots = cli.require_existing_dirs(args.roots, "spelling")
    cli.require_distinct_site_names(roots, "spelling")
    baseline_dir = Path(args.baseline_dir)
    overall = 0
    for root in roots:
        bpath = _baseline_path(baseline_dir, root)
        baseline = parse_baseline(bpath) if bpath.is_file() else set()
        try:
            new, all_keys = scan_root(root, args.config, set() if args.write_baseline else baseline)
        except FileNotFoundError:
            # cspell is a sandbox Depends; its absence is an ENVIRONMENT BUG, a loud fatal.
            print("spelling: FATAL: cspell not found -- it is required (installed in the review "
                  "sandbox); install it, do not skip the scan", file=sys.stderr)
            return 1
        except RuntimeError as exc:
            print("spelling: FAIL %s: cspell error: %s" % (cli.site_name(root), exc),
                  file=sys.stderr)
            overall = 1
            continue
        name = cli.site_name(root)
        if args.write_baseline:
            baseline_dir.mkdir(parents=True, exist_ok=True)
            bpath.write_text(format_baseline(all_keys, site=name), encoding="utf-8")
            print("spelling: seeded %d accepted word(s) -> %s" % (len(all_keys), bpath),
                  file=sys.stderr)
            continue
        if new:
            for key in sorted(new):
                print("%s: MISSPELLING %s" % (name, key))
            print("%s: FAIL -- %d newly-unknown word(s)" % (name, len(new)))
            overall = 1
        else:
            print("%s: ok -- no newly-unknown words" % name)
    return overall


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
