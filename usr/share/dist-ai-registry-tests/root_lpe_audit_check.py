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
    ("vuln-refusal-elsewhere", "home-recursive-write", "HIGH"),  ## refusal text outside root_check body
    ("vuln-mixed-body", "home-recursive-write", "HIGH"),         ## refusal text inside a real root_check
    ("vuln-text-cross-clause", "home-recursive-write", "HIGH"),  ## 'do not run ...' spanning clauses
    ("vuln-text-both", "home-recursive-write", "HIGH"),          ## separate refusal beside a root gate
]

## Paths that must have ZERO findings: the safe counterparts, AND a root-guarded
## home-write vuln under ci/ that must never enter the root surface (no FHS
## install path -> not a shipped root entry point), AND a launcher whose own
## root_check refuses root, AND an inline refusal message.
SAFE_PATHS = ("safe-boot", "safe-guarded", "safe-round2", "vuln-ci",
              "safe-env-dashdash", "safe-env-expand", "safe-refuses-root",
              "safe-text-refusal")


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

    def reason_of(path_sub, rule, op_sub):
        for f in suppressed:
            if (path_sub in f["path"] and f["rule"] == rule
                    and op_sub in f["tainted_operand"]):
                return f.get("waiver_reason", "")
        return None

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
    ## A waiver wrapped over a CONTIGUOUS standalone comment block is honored
    ## wherever it sits in the block; a blank or code line ends the block.
    for op_sub in (".wrap2", ".wrap3", ".wrapmid"):
        checks.append((
            "wrapped waiver block suppresses the %s sink" % op_sub,
            has(suppressed, "vuln-waived", "symlink-follow", op_sub,
                need_reason=True)
            and not has(findings, "vuln-waived", "symlink-follow", op_sub)))
    for op_sub, sep in ((".blanksep", "blank"), (".codesep", "code")):
        checks.append((
            "waiver cut off by a %s line does not suppress the %s sink"
            % (sep, op_sub),
            has(findings, "vuln-waived", "symlink-follow", op_sub)
            and not has(suppressed, "vuln-waived", "symlink-follow", op_sub)))
    checks.append((
        "wrapped waiver reason carries every wrapped line",
        reason_of("vuln-waived", "symlink-follow", ".wrap3")
        == "wrapped reason, first line of a three-line waiver block, third line."))
    checks.append((
        "waiver syntax quoted mid-comment is not a waiver",
        has(findings, "vuln-waived", "symlink-follow", ".quoted")
        and not has(suppressed, "vuln-waived", "symlink-follow", ".quoted")))
    checks.append((
        "a comment-ending backslash does not cut the waiver block",
        has(suppressed, "vuln-waived", "symlink-follow", ".cbs",
            need_reason=True)
        and not has(findings, "vuln-waived", "symlink-follow", ".cbs")))
    checks.append((
        "the nearest waiver's reason wins",
        reason_of("vuln-waived", "symlink-follow", ".near")
        == "near trailing reason"))
    checks.append((
        "python waiver in a deeper-indented suite does not reach a dedented op",
        has(findings, "vuln_py_waived", "python-advisory", ".cache")
        and not has(suppressed, "vuln_py_waived", "python-advisory", ".cache")))
    checks.append((
        "python wrapped waiver block suppresses the advisory",
        has(suppressed, "vuln_py_waived", "python-advisory", ".local",
            need_reason=True)
        and not has(findings, "vuln_py_waived", "python-advisory", ".local")))
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
    ## Python statement spans (ast): a finding on a LATER line of a multi-line
    ## statement resolves to its first line, where the waiver sits above it; a
    ## compound statement's span is its header only, so a waiver above 'if'
    ## does not reach the body; an unparseable file honors no waiver.
    checks.append((
        "python waiver above a multi-line statement suppresses a later-line op",
        has(suppressed, "vuln_py_waived", "python-advisory", ".multiline",
            need_reason=True)
        and not has(findings, "vuln_py_waived", "python-advisory", ".multiline")))
    checks.append((
        "python waiver above an 'if' header does not reach its body",
        has(findings, "vuln_py_waived", "python-advisory", ".ifbody")
        and not has(suppressed, "vuln_py_waived", "python-advisory", ".ifbody")))
    ## One-liner colon-suites (header + body share a physical line) and a post-';'
    ## statement: the comment block above the line documents the LEADING
    ## statement, so a sink in the body/trailing statement must stay FLAGGED.
    for op_sub, header in ((".if1liner", "if"), (".for1liner", "for"),
                           (".with1liner", "with"),
                           (".def1liner", "def"), (".semicolon", "';'")):
        checks.append((
            "python waiver above a one-liner %s does not reach its body" % header,
            has(findings, "vuln_py_waived", "python-advisory", op_sub)
            and not has(suppressed, "vuln_py_waived", "python-advisory", op_sub)))
    ## Precision canary: when the sink IS in the header of a one-liner, the block
    ## above legitimately waives it -- proving the fix is column-precise, not a
    ## blunt refusal of every one-liner block-above waiver.
    checks.append((
        "python waiver above a one-liner header reaches a sink in that header",
        has(suppressed, "vuln_py_waived", "python-advisory", ".ifheader",
            need_reason=True)
        and not has(findings, "vuln_py_waived", "python-advisory", ".ifheader")))
    checks.append((
        "python trailing waiver on a wrapped case pattern does not reach the guard",
        has(findings, "vuln_py_waived", "python-advisory", ".casetrail")
        and not has(suppressed, "vuln_py_waived", "python-advisory",
                    ".casetrail")))
    for op_sub, header in ((".excepthdr", "except"), (".caseguard", "case"),
                           (".caseparen", "case (")):
        checks.append((
            "python waiver above a wrapped '%s' header suppresses its op"
            % header,
            has(suppressed, "vuln_py_waived", "python-advisory", op_sub,
                need_reason=True)
            and not has(findings, "vuln_py_waived", "python-advisory", op_sub)))
    checks.append((
        "python form feed does not shift the advisory onto a waiver line",
        has(findings, "vuln_py_formfeed", "python-advisory", ".formfeed")
        and not has(suppressed, "vuln_py_formfeed", "python-advisory",
                    ".formfeed")))
    checks.append((
        "python waiver in an unparseable file is not honored",
        has(findings, "vuln_py_unparsed", "python-advisory", ".unparsed")
        and not has(suppressed, "vuln_py_unparsed", "python-advisory",
                    ".unparsed")))
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
