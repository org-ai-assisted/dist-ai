#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_test.sh.

Standalone (reads the report JSON named on argv, NOT stdin) and eval-free.
Asserts: every planted vuln is found at its expected rule + minimum severity;
each SAFE counterpart is clean (no finding); the reachability engine resolved
the cross-submodule, root-guarded and '#pkg'-suffix cases; and coverage is
non-trivial (a zero-coverage run is not a silent green). Prints 'N pass, N fail'.
"""

import json
import sys

SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH")

## (path substring, rule, minimum severity) that MUST appear.
EXPECTED = [
    ("vuln-boot", "home-recursive-write", "HIGH"),
    ("vuln-guarded", "home-recursive-write", "HIGH"),      ## find -delete
    ("vuln-guarded", "symlink-follow", "HIGH"),            ## cp -L
    ("vuln-guarded", "world-writable-perms", "MEDIUM"),    ## chmod 777
    ("vuln-guarded", "tmp-race", "MEDIUM"),                ## > /dev/shm/...
    ("vuln-guarded", "path-hijack", "MEDIUM"),             ## PATH=.:...
    ("vuln-guarded", "untrusted-source-eval", "HIGH"),     ## . "$home/..."
    ("postinst", "home-recursive-write", "HIGH"),          ## chown -R $SUDO_USER
    ("postinst", "trust-sudo-user", "HIGH"),               ## $SUDO_USER unvalidated
    ("vuln-wrappers", "home-recursive-write", "MEDIUM"),   ## command-peel + --target-directory + declare
    ("vuln-wrappers", "world-writable-perms", "MEDIUM"),   ## chmod --recursive 777
]

## Paths that must have ZERO findings: the safe counterparts, AND a root-guarded
## home-write vuln under ci/ that must never enter the root surface (no FHS
## install path -> not a shipped root entry point).
SAFE_PATHS = ("safe-boot", "safe-guarded", "vuln-ci")


def _sev_ok(actual, minimum):
    return SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(minimum)


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: root_lpe_audit_check.py <report.json>", file=sys.stderr)
        return 1
    with open(argv[1], "r", encoding="utf-8") as handle:
        report = json.load(handle)
    findings = report.get("findings", [])
    coverage = report.get("coverage", {})

    checks = []

    ## Schema pin.
    checks.append(("schema is dm-root-lpe-audit/1",
                   report.get("schema") == "dm-root-lpe-audit/1"))

    ## Planted vulns found at the right rule + severity.
    for path_sub, rule, min_sev in EXPECTED:
        hit = any(
            path_sub in f["path"] and f["rule"] == rule
            and _sev_ok(f["severity"], min_sev)
            for f in findings)
        checks.append(("planted %s in %s at >= %s" % (rule, path_sub, min_sev),
                       hit))

    ## Safe counterparts clean.
    for path_sub in SAFE_PATHS:
        clean = not any(path_sub in f["path"] for f in findings)
        checks.append(("safe %s has no findings" % path_sub, clean))

    ## Reachability engine: cross-submodule unit -> ExecStart target.
    cross = any(
        "vuln-boot" in f["path"] and "systemd-unit" in f["root_reason"]
        for f in findings)
    checks.append(("cross-submodule unit resolves to its ExecStart target", cross))

    ## Reachability engine: self-gated root helper found via root-guard signal.
    guarded = any(
        "vuln-guarded" in f["path"] and "root-guarded-script" in f["root_reason"]
        for f in findings)
    checks.append(("root-guarded self-gated script is reached", guarded))

    ## Coverage is real, not a silent green.
    checks.append(("root_files coverage >= 5", coverage.get("root_files", 0) >= 5))
    checks.append(("shell_scanned coverage >= 5",
                   coverage.get("shell_scanned", 0) >= 5))
    checks.append(("no parse errors", not coverage.get("parse_errors")))
    checks.append(("no walk errors", not coverage.get("walk_errors")))

    passed = 0
    failed = 0
    for description, ok in checks:
        if ok:
            passed += 1
            print("PASS: %s" % description)
        else:
            failed += 1
            print("FAIL: %s" % description)
    print("")
    print("root-lpe-audit: %d pass, %d fail" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
