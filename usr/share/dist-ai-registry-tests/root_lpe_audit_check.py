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
    ("vuln-round2", "home-recursive-write", "HIGH"),       ## find -L ... -delete
    ("vuln-round2", "symlink-follow", "HIGH"),             ## dd of= home
    ("vuln-round2", "world-writable-perms", "MEDIUM"),     ## chmod a=w
    ("vuln-env-single", "home-recursive-write", "MEDIUM"), ## env -- VAR=val chown
    ("vuln-env-multi", "home-recursive-write", "MEDIUM"),  ## env -- A=1 B=2 chown (loop)
    ("vuln-env-nonid", "home-recursive-write", "MEDIUM"),  ## env -- X-Y=1 chown (non-identifier name)
    ("vuln-env-expand", "home-recursive-write", "MEDIUM"), ## env -- "PATH=$PATH" chown (raw '=' test)
    ("vuln-env-dash", "home-recursive-write", "MEDIUM"),   ## env -- - PATH=.. chown (lone '-')
]

## Paths that must have ZERO findings: the safe counterparts, AND a root-guarded
## home-write vuln under ci/ that must never enter the root surface (no FHS
## install path -> not a shipped root entry point).
SAFE_PATHS = ("safe-boot", "safe-guarded", "safe-round2", "vuln-ci",
              "safe-env-dashdash", "safe-env-expand")


def _sev_ok(actual, minimum):
    return SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(minimum)


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: root_lpe_audit_check.py <report.json>", file=sys.stderr)
        return 1
    with open(argv[1], "r", encoding="utf-8") as handle:
        report = json.load(handle)
    findings = report.get("findings", [])
    suppressed = report.get("suppressed", [])
    coverage = report.get("coverage", {})

    def has(items, path_sub, rule, op_sub=None, need_reason=False):
        for f in items:
            if path_sub not in f["path"] or f["rule"] != rule:
                continue
            if op_sub is not None and op_sub not in f["tainted_operand"]:
                continue
            if need_reason and not f.get("waiver_reason", "").strip():
                continue
            return True
        return False

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

    ## Per-line by-design waiver: routes ONLY the named rule to 'suppressed'
    ## (still visible), surgically, without over- or under-suppressing.
    checks.append(("report carries a 'suppressed' list", "suppressed" in report))
    checks.append((
        "waived symlink-follow routed to suppressed with a reason",
        has(suppressed, "vuln-waived", "symlink-follow", ".bashrc",
            need_reason=True)))
    checks.append((
        "waived symlink-follow removed from findings",
        not has(findings, "vuln-waived", "symlink-follow", ".bashrc")))
    checks.append((
        "continuation waiver (line above a '\\' split) suppresses the sink",
        has(suppressed, "vuln-waived", "home-recursive-write", ".config",
            need_reason=True)))
    checks.append((
        "continuation-waived home-recursive-write removed from findings",
        not has(findings, "vuln-waived", "home-recursive-write", ".config")))
    checks.append((
        "per-rule: other rule on the waived line stays flagged",
        has(findings, "vuln-waived", "root-write-user-path", ".bashrc")))
    checks.append((
        "un-waived identical-rule sink stays flagged",
        has(findings, "vuln-waived", "symlink-follow", ".profile")))
    checks.append((
        "reason-less waiver is NOT honored (finding still fires)",
        has(findings, "vuln-waived", "world-writable-perms")))
    ## Mis-association guard: a waiver above a DIFFERENT statement must not leak
    ## onto a sink below it via a comment/'\\' line (the AST-truthful boundary,
    ## not a textual continuation scan).
    checks.append((
        "sink below a comment-'\\' line stays flagged (no mis-association)",
        has(findings, "vuln-waived", "symlink-follow", ".bash_logout")))
    checks.append((
        "that sink is NOT wrongly suppressed",
        not has(suppressed, "vuln-waived", "symlink-follow", ".bash_logout")))
    ## A 'style-ok' sitting in a QUOTED STRING (on a line whose real comment is
    ## unrelated) is data, not a waiver -- the sink below must stay flagged.
    checks.append((
        "quoted-string '#style-ok' does not waive the sink below",
        has(findings, "vuln-waived", "symlink-follow", ".bash_history")))
    checks.append((
        "quoted-string smuggle sink is NOT suppressed",
        not has(suppressed, "vuln-waived", "symlink-follow", ".bash_history")))
    ## A TRAILING waiver on the code line directly above a finding belongs to
    ## THAT line's statement, not the finding below -- only a STANDALONE comment
    ## above a statement waives it. Guards both the shell and Python paths.
    checks.append((
        "trailing waiver on the line above a shell sink does not suppress it",
        has(findings, "vuln-waived", "symlink-follow", ".inputrc")
        and not has(suppressed, "vuln-waived", "symlink-follow", ".inputrc")))
    ## A comment that is a '\\' line-continuation of the statement ABOVE it is not
    ## a standalone waiver, so it must not suppress the sink below.
    checks.append((
        "continuation-comment above a sink does not suppress it",
        has(findings, "vuln-waived", "symlink-follow", ".dircolors")
        and not has(suppressed, "vuln-waived", "symlink-follow", ".dircolors")))
    ## Python path: a 'style-ok' inside a MULTI-LINE string is a string token,
    ## not a comment, so it must not waive the advisory finding below it. The
    ## 'in findings' half also proves the python-advisory path is exercised (no
    ## vacuous pass).
    checks.append((
        "python-advisory finding emitted for the py fixture",
        has(findings, "vuln_py_waived", "python-advisory", ".config")))
    checks.append((
        "python multi-line-string '#style-ok' does not waive the advisory",
        not has(suppressed, "vuln_py_waived", "python-advisory", ".config")))
    checks.append((
        "python trailing waiver above an advisory does not suppress it",
        has(findings, "vuln_py_waived", "python-advisory", ".ssh")
        and not has(suppressed, "vuln_py_waived", "python-advisory", ".ssh")))
    checks.append(("coverage.suppressed >= 2", coverage.get("suppressed", 0) >= 2))

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
