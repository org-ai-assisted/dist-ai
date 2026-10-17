## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Secret-scan of the BUILT site tree: flag an accidentally-published API key, token, private
key, or credential in the emitted HTML/CSS/JS.

The one security category with ZERO N/A for a static site: the bytes are public, so a secret
in them is an irreversible leak. Delegates detection to `gitleaks` (regex + entropy, offline,
read-only) over the built tree -- the industry baseline -- and gates on a per-site accepted
baseline so a reviewed false positive does not re-fail (like the extlinks lane).

gitleaks output is REDACTED (`--redact`), so the secret value never reaches a log / CI output /
this gate's stderr -- only the rule id + file:line locate it for a human to rotate + remove.

gitleaks is a hard dependency of this package (debian/control Depends): it is ASSUMED present
and called directly. Its absence is an ENVIRONMENT BUG that FAILS LOUD (exit 1), never a SKIP --
a secret-scan that silently did not run is exactly the false green this gate exists to prevent.
Pure JSON parsing + baseline; only `_run_gitleaks` shells out.
"""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 -- invokes the fixed gitleaks binary, no shell, no user input in argv
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# gitleaks finding fields we keep (RuleID + location); Secret/Match are intentionally dropped --
# never echo a secret value, even redacted upstream.
_KEEP = ("RuleID", "File", "StartLine", "Fingerprint")


def _run_gitleaks(root: str) -> List[dict]:
    """Run gitleaks over `root` (no git, read-only, redacted) and return its JSON findings.

    gitleaks is a hard dependency, so it is called directly (no has-X preflight). A missing
    binary surfaces as FileNotFoundError and a gitleaks error as RuntimeError; main() turns
    either into a loud exit-1 FAILURE, never a skip."""
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "gitleaks.json")
        # Debian ships gitleaks 8.16 -> `detect --no-git --source`; --redact keeps secret values
        # out of the report, --report-path writes JSON we parse (exit code alone is unreliable).
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell=True, paths are ours
            ["gitleaks", "detect", "--no-git", "--source", root,
             "--report-format", "json", "--report-path", report,
             "--redact", "--no-banner", "--exit-code", "0"],
            capture_output=True, text=True)
        try:
            with open(report, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise RuntimeError("gitleaks wrote no report (rc=%d): %s"
                               % (proc.returncode, (proc.stderr or "")[-300:]))
        except json.JSONDecodeError as exc:
            raise RuntimeError("gitleaks report is not valid JSON: %s" % exc)
    return data if isinstance(data, list) else []


def finding_key(finding: dict) -> str:
    """Stable fingerprint for baselining. Prefer gitleaks' own Fingerprint; else File:RuleID:line
    (relative, so a different checkout path does not change the key)."""
    fp = finding.get("Fingerprint")
    if fp:
        return str(fp)
    return "%s:%s:%s" % (finding.get("File", ""), finding.get("RuleID", ""),
                         finding.get("StartLine", ""))


def scan_root(root: str, baseline: Set[str]) -> Tuple[List[dict], Set[str]]:
    """(new_findings, all_keys): new_findings are those whose key is NOT in `baseline` (the gate
    failures); all_keys is every finding's key (for re-seeding a baseline). File paths are made
    root-relative so a finding reads + baselines independent of the checkout location."""
    findings = _run_gitleaks(root)
    new: List[dict] = []
    all_keys: Set[str] = set()
    for f in findings:
        rel = os.path.relpath(f.get("File", root), root) if f.get("File") else ""
        trimmed = {k: f.get(k) for k in _KEEP}
        trimmed["File"] = rel
        key = finding_key(f)
        all_keys.add(key)
        if key not in baseline:
            trimmed["_key"] = key
            new.append(trimmed)
    return new, all_keys


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
        "# Secret-scan: accepted gitleaks finding fingerprints%s (one per line)." % who,
        "# A fingerprint listed here is tolerated (reviewed false positive / test fixture).",
        "# The gate flags only a NEWLY-found secret. Prune when the cause is removed.",
    ]
    return "\n".join(header + sorted(keys)) + "\n"


def _baseline_path(baseline_dir: Path, root: str) -> Path:
    return baseline_dir / ("secrets-baseline-%s.txt"
                           % os.path.basename(os.path.normpath(root)))


def main(argv: List[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Secret-scan the built site tree (gitleaks).")
    ap.add_argument("--baseline-dir", required=True,
                    help="dir holding secrets-baseline-<site>.txt")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record the current findings as the accepted baseline instead of gating")
    ap.add_argument("roots", nargs="+")
    args = ap.parse_args(argv)
    roots = [os.path.abspath(r) for r in args.roots if os.path.isdir(r)]
    if not roots:
        print("secrets: SKIP (no site root found)", file=sys.stderr)  ## style-ok: allow-skip: no target tree
        return 77
    baseline_dir = Path(args.baseline_dir)
    overall = 0
    for root in roots:
        bpath = _baseline_path(baseline_dir, root)
        baseline = parse_baseline(bpath) if bpath.is_file() else set()
        try:
            new, all_keys = scan_root(root, set() if args.write_baseline else baseline)
        except FileNotFoundError:
            # gitleaks is a Depends; its absence is an ENVIRONMENT BUG, a loud fatal, not a skip.
            print("secrets: FATAL: gitleaks not found -- it is a required dependency "
                  "(dist-ai Depends); install it, do not skip the scan", file=sys.stderr)
            return 1
        except RuntimeError as exc:
            print("secrets: FAIL %s: gitleaks error: %s" % (os.path.basename(root), exc),
                  file=sys.stderr)
            overall = 1
            continue
        name = os.path.basename(root)
        if args.write_baseline:
            baseline_dir.mkdir(parents=True, exist_ok=True)
            bpath.write_text(format_baseline(all_keys, site=name), encoding="utf-8")
            print("secrets: seeded %d accepted finding(s) -> %s" % (len(all_keys), bpath),
                  file=sys.stderr)
            continue
        if new:
            for f in new:
                print("%s: SECRET %s in %s:%s -- rotate + remove (value redacted)"
                      % (name, f.get("RuleID"), f.get("File"), f.get("StartLine")))
            print("%s: FAIL -- %d newly-detected secret(s)" % (name, len(new)))
            overall = 1
        else:
            print("%s: ok -- no newly-detected secrets" % name)
    return overall


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
