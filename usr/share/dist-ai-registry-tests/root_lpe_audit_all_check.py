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
                     "malformed_tree", "second_clean"):
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

        ## default tree is CWD when no args are given.
        env = dict(os.environ, DM_ROOT_LPE_AUDIT=stub)
        proc = subprocess.run([subject], capture_output=True, text=True,
                              check=False, env=env,
                              cwd=os.path.join(work, "clean_tree"))
        check("no args defaults to CWD -> exit 0", proc.returncode == 0, checks)

        ## Real-auditor smoke: no override, default sibling resolution, a missing
        ## tree is reported before the auditor is even invoked -> exit 2.
        env = dict(os.environ)
        env.pop("DM_ROOT_LPE_AUDIT", None)
        proc = subprocess.run([subject, os.path.join(work, "no_such_tree")],
                              capture_output=True, text=True, check=False, env=env)
        check("real-auditor path runs end to end (missing tree -> exit 2)",
              proc.returncode == 2 and "SCAN ERROR" in proc.stdout + proc.stderr,
              checks)

    passed = sum(1 for _, ok in checks if ok)
    failed = len(checks) - passed
    for desc, ok in checks:
        print("%s: %s" % ("PASS" if ok else "FAIL", desc))
    print("")
    print("root-lpe-audit-all: %d pass, %d fail" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
