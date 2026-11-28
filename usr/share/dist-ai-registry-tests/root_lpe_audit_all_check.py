#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_all_test.sh.

Drives the REAL dm-root-lpe-audit-all (argv[1]) over fixture trees, with its
auditor overridden (DM_ROOT_LPE_AUDIT) to a STUB that emits canned per-tree JSON
(a controlled INPUT, not a copy of the subject). This pins the wrapper's OWN
logic -- aggregation and the exit contract -- deterministically, without a heavy
real audit:
  EXIT 0 every tree clean; EXIT 1 any open candidate; EXIT 2 any scan error
  (missing tree, no JSON, or parse/walk-degraded), and a scan error OUTRANKS a
  finding in the exit code. A final real-auditor smoke proves the default
  sibling resolution runs end to end. Prints 'N pass, N fail'.
"""

import os
import stat
import subprocess
import sys
import tempfile

STUB = r'''#!/usr/bin/python3
import json, os, sys
name = os.path.basename(os.path.normpath(sys.argv[1]))
r = {"coverage": {"root_files": 5, "shell_scanned": 4, "sinks_examined": 10,
                  "unresolved_targets": 2, "parse_errors": [], "walk_errors": []},
     "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
     "findings": [], "suppressed": []}
if name == "clean_tree":
    r["suppressed"] = [{"severity": "HIGH"}]
elif name == "finding_tree":
    r["severity_counts"]["HIGH"] = 1
    r["findings"] = [{"severity": "HIGH", "path": "usr/bin/x", "line": 9,
                      "rule": "symlink-follow", "tainted_operand": "\"${p}\"",
                      "root_reason": "root-guarded-script"}]
elif name == "degraded_tree":
    r["coverage"]["parse_errors"] = [{"path": "usr/bin/y", "error": "boom"}]
elif name == "noout_tree":
    sys.stderr.write("stub: simulated failure\n")
    sys.exit(1)
elif name == "malformed_tree":
    ## valid JSON, right top-level keys, WRONG container types: coverage is null.
    ## The wrapper's contract makes this a scan error (exit 2), never a crash.
    print('{"coverage": null, "severity_counts": null, "findings": null}')
    sys.exit(0)
elif name == "wrongroot_tree":
    ## a VALID report but the auditor EXITS NONZERO: its "wrong root?" advisory
    ## (coverage.root_files == 0). A mis-pointed/empty scan must be a scan error,
    ## never accepted as a usable clean scan.
    print(json.dumps({"coverage": {"root_files": 0, "shell_scanned": 0,
          "sinks_examined": 0, "unresolved_targets": 0, "parse_errors": [],
          "walk_errors": []},
          "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
          "findings": [], "suppressed": []}))
    sys.exit(1)
elif name == "nested_bad_tree":
    ## right TOP-LEVEL types, wrong NESTED values: parse_errors null (len crash), a
    ## severity_counts value a string (int/%d crash), suppressed null (len crash).
    print('{"coverage": {"root_files": 1, "shell_scanned": 1, "sinks_examined": 1,'
          ' "unresolved_targets": 0, "parse_errors": null, "walk_errors": null},'
          ' "severity_counts": {"HIGH": "x", "MEDIUM": 0, "LOW": 0, "INFO": 0},'
          ' "findings": [], "suppressed": null}')
    sys.exit(0)
print(json.dumps(r))
'''


def run(subject, trees, workdir, stub, cwd=None):
    env = dict(os.environ, DM_ROOT_LPE_AUDIT=stub)
    paths = [os.path.join(workdir, t) for t in trees]
    proc = subprocess.run([subject, *paths], capture_output=True, text=True,
                          check=False, env=env, cwd=cwd)
    return proc.returncode, proc.stdout + proc.stderr


def check(desc, cond, checks):
    checks.append((desc, bool(cond)))


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: root_lpe_audit_all_check.py <dm-root-lpe-audit-all>",
              file=sys.stderr)
        return 1
    subject = argv[1]
    if not os.path.isfile(subject):
        print("FATAL: subject not found: %s" % subject, file=sys.stderr)
        return 1

    checks: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="lpe-all-") as work:
        stub = os.path.join(work, "stub-audit")
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write(STUB)
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR | stat.S_IXGRP
                 | stat.S_IXOTH)
        for name in ("clean_tree", "finding_tree", "degraded_tree", "noout_tree",
                     "malformed_tree", "wrongroot_tree", "nested_bad_tree",
                     "second_clean"):
            os.mkdir(os.path.join(work, name))

        rc, out = run(subject, ["clean_tree", "second_clean"], work, stub)
        check("all-clean trees -> exit 0", rc == 0, checks)
        check("clean run reports 0 open candidates",
              "open candidates: 0 HIGH" in out, checks)

        rc, out = run(subject, ["finding_tree"], work, stub)
        check("a finding -> exit 1", rc == 1, checks)
        check("finding row is printed", "[HIGH" in out and "symlink-follow" in out,
              checks)
        check("aggregate counts the finding tree", "across 1 tree" in out, checks)

        rc, out = run(subject, ["clean_tree", "finding_tree"], work, stub)
        check("clean+finding -> exit 1", rc == 1, checks)
        check("mixed aggregate is 1 HIGH across 1 tree",
              "1 HIGH" in out and "across 1 tree" in out, checks)

        rc, out = run(subject, ["degraded_tree"], work, stub)
        check("parse/walk-degraded -> exit 2 (scan error)", rc == 2, checks)
        check("degraded tree is flagged", "DEGRADED" in out, checks)

        rc, out = run(subject, ["finding_tree", "degraded_tree"], work, stub)
        check("scan error OUTRANKS a finding in the exit code", rc == 2, checks)

        rc, out = run(subject, ["no_such_tree"], work, stub)
        check("missing tree -> exit 2", rc == 2, checks)
        check("missing tree is a SCAN ERROR", "SCAN ERROR" in out
              and "not a directory" in out, checks)

        rc, out = run(subject, ["noout_tree"], work, stub)
        check("auditor with no JSON -> exit 2", rc == 2, checks)
        check("no-JSON is a SCAN ERROR", "auditor produced no JSON" in out, checks)

        rc, out = run(subject, ["malformed_tree"], work, stub)
        check("a parseable-but-malformed report -> exit 2 (not a crash/finding)",
              rc == 2, checks)
        check("malformed report is a SCAN ERROR", "SCAN ERROR" in out, checks)

        rc, out = run(subject, ["wrongroot_tree"], work, stub)
        check("auditor nonzero exit (wrong root) -> exit 2, not accepted as clean",
              rc == 2, checks)
        check("wrong-root run is a SCAN ERROR", "SCAN ERROR" in out, checks)

        rc, out = run(subject, ["nested_bad_tree"], work, stub)
        check("a nested-malformed report -> exit 2 (no uncaught crash)",
              rc == 2, checks)

        ## A missing/unlaunchable auditor must be a scan error, not an OSError crash.
        env = dict(os.environ, DM_ROOT_LPE_AUDIT=os.path.join(work, "no-such-auditor"))
        proc = subprocess.run([subject, os.path.join(work, "clean_tree")],
                              capture_output=True, text=True, check=False, env=env)
        check("an unlaunchable auditor -> exit 2 (scan error, not a traceback)",
              proc.returncode == 2, checks)

        ## default tree is CWD when no args are given.
        env = dict(os.environ, DM_ROOT_LPE_AUDIT=stub)
        proc = subprocess.run([subject], capture_output=True, text=True,
                              check=False, env=env,
                              cwd=os.path.join(work, "clean_tree"))
        check("no args defaults to CWD -> exit 0", proc.returncode == 0, checks)

        ## Pre-launch guard with the DEFAULT sibling auditor (no override): a missing
        ## tree is reported before the auditor is invoked -> exit 2.
        env = dict(os.environ)
        env.pop("DM_ROOT_LPE_AUDIT", None)
        proc = subprocess.run([subject, os.path.join(work, "no_such_tree")],
                              capture_output=True, text=True, check=False, env=env)
        check("default sibling resolution: a missing tree -> exit 2",
              proc.returncode == 2 and "SCAN ERROR" in proc.stdout + proc.stderr,
              checks)

        ## Real-auditor smoke: a tree with a GENUINE root surface (a system unit whose
        ## ExecStart script writes under $HOME), driven by the DEFAULT sibling auditor
        ## -- proves the wrapper runs the REAL auditor end to end and returns a verdict,
        ## not just the pre-launch guards. The auditor's deps (shfmt) are a hard
        ## requirement; their absence fails here, it is not skipped.
        smoke = os.path.join(work, "smoke_tree")
        os.makedirs(os.path.join(smoke, "usr/lib/systemd/system"))
        os.makedirs(os.path.join(smoke, "usr/bin"))
        with open(os.path.join(smoke, "usr/lib/systemd/system/smoke.service"),
                  "w", encoding="utf-8") as fh:
            fh.write("[Service]\nExecStart=/usr/bin/smoke-root\n")
        with open(os.path.join(smoke, "usr/bin/smoke-root"), "w",
                  encoding="utf-8") as fh:
            fh.write('#!/bin/bash\ncp --recursive -- "${src}" "${HOME}/dest"\n')
        proc = subprocess.run([subject, smoke], capture_output=True, text=True,
                              check=False, env=env)
        smoke_out = proc.stdout + proc.stderr
        check("real-auditor smoke: the sibling auditor actually scanned the tree",
              "=== smoke_tree ===" in smoke_out and "0 root files" not in smoke_out,
              checks)
        check("real-auditor smoke: a genuine finding yields exit 1 (a real verdict)",
              proc.returncode == 1, checks)

    passed = sum(1 for _, ok in checks if ok)
    failed = len(checks) - passed
    for desc, ok in checks:
        print("%s: %s" % ("PASS" if ok else "FAIL", desc))
    print("")
    print("root-lpe-audit-all: %d pass, %d fail" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
