#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Comprehensive test + fuzz for lockfile.sh (helper-scripts) -- the atomic
## 'flock' FLOCKER re-exec mutex, in both of its modes:
##
##   * SOURCE mode -- a script sources it to self-lock: a second instance of the
##     same script SKIPS while the first holds the lock and runs once released;
##     the optional LOCK_NAME override locks PER KEY (same key skips, distinct
##     keys run concurrently), and an unset LOCK_NAME self-locks by the script's
##     own path; a path-like key is handled.
##
##   * WRAP mode -- 'lockfile.sh <lock-key> -- <command>' runs the command under
##     a per-key lock: per-key skip/concurrency, exit-code propagation, the
##     command inherits neither LOCK_NAME nor FLOCKER, a command that itself
##     sources lockfile does NOT self-deadlock, and the usage guards.
##
## A fuzz phase hammers random keys through wrap mode and asserts per-key
## isolation against a key-equality oracle.
##
## No root, no network. The subject is the installed
## /usr/libexec/helper-scripts/lockfile.sh; set LOCKFILE_SH to an explicit file
## or LOCKFILE_SH_REPO to a helper-scripts checkout to test that instead. There
## are NO skip paths: a missing or feature-incomplete lockfile.sh FAILS.
##
## Usage: lockfile_test.py [--iterations N] [--seed N] [--fuzz-only]

import argparse
import os
import random
import stat
import subprocess
import sys
import tempfile
import time

LOCKFILE_SH_REPO = os.environ.get("LOCKFILE_SH_REPO")


def lockfile_sh_path():
    direct = os.environ.get("LOCKFILE_SH")
    if direct:
        return direct
    if LOCKFILE_SH_REPO:
        return os.path.join(LOCKFILE_SH_REPO,
                            "usr/libexec/helper-scripts/lockfile.sh")
    return "/usr/libexec/helper-scripts/lockfile.sh"


def write_exec(path, content):
    with open(path, "w", encoding="ascii") as handle:
        handle.write(content)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP
             | stat.S_IXOTH)


def run(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def bg(argv):
    return subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def make_source_script(tmp, lockfile_sh):
    """A script that sources lockfile.sh (optional LOCK_NAME from $1), then
    prints LOCKED and sleeps $2 -- run concurrently to observe the lock."""
    path = os.path.join(tmp, "src_lock.sh")
    write_exec(path,
               "#!/bin/bash\n"
               "set -o errexit\n"
               "set -o nounset\n"
               "if [ -n \"${1:-}\" ]; then LOCK_NAME=\"$1\"; fi\n"
               "source %s\n"
               "echo LOCKED\n"
               "sleep \"${2:-0}\"\n" % lockfile_sh)
    return path


def source_mode_tests(lockfile_sh, check):
    tmp = tempfile.mkdtemp(prefix="lockfile-src-")
    src = make_source_script(tmp, lockfile_sh)

    ## self-lock (no key): 2nd instance skips (non-zero) while the 1st holds it.
    holder = bg([src, "", "2"])
    time.sleep(0.6)
    second = run([src, "", "0"])
    check("source: self-lock 2nd instance skips", "LOCKED" not in second.stdout,
          second.stdout.strip())
    check("source: skip exits non-zero", second.returncode != 0,
          "rc=%d" % second.returncode)
    holder.wait(timeout=15)
    third = run([src, "", "0"])
    check("source: re-acquirable after release", "LOCKED" in third.stdout,
          third.stdout.strip())

    ## LOCK_NAME per-key: same key skips, different key runs concurrently.
    holder = bg([src, "keyA", "2"])
    time.sleep(0.6)
    same = run([src, "keyA", "0"])
    other = run([src, "keyB", "0"])
    check("source: LOCK_NAME same key skips", "LOCKED" not in same.stdout,
          same.stdout.strip())
    check("source: LOCK_NAME different key concurrent", "LOCKED" in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## a path-like key (contains '/' and '.') is handled.
    keyed = run([src, "svc/onionv3.rend", "0"])
    check("source: path-like key handled",
          "LOCKED" in keyed.stdout and keyed.returncode == 0,
          keyed.stdout.strip())


def wrap_mode_tests(lockfile_sh, check):
    tmp = tempfile.mkdtemp(prefix="lockfile-wrap-")

    ## per-key: same key skips (rc!=0, command not run), different concurrent.
    holder = bg([lockfile_sh, "wA", "--", "sleep", "2"])
    time.sleep(0.6)
    same = run([lockfile_sh, "wA", "--", "echo", "RAN"])
    other = run([lockfile_sh, "wB", "--", "echo", "RAN"])
    check("wrap: same key skips", "RAN" not in same.stdout
          and same.returncode != 0,
          "%r rc=%d" % (same.stdout.strip(), same.returncode))
    check("wrap: different key concurrent", "RAN" in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## exit-code propagation.
    rc7 = run([lockfile_sh, "wC", "--", "bash", "-c", "exit 7"])
    check("wrap: propagates exit code", rc7.returncode == 7,
          "rc=%d" % rc7.returncode)

    ## the wrapped command inherits neither LOCK_NAME nor FLOCKER.
    probe = os.path.join(tmp, "probe.sh")
    write_exec(probe,
               "#!/bin/bash\n"
               "echo \"L=${LOCK_NAME:-unset} F=${FLOCKER:-unset}\"\n")
    leak = run([lockfile_sh, "wD", "--", probe])
    check("wrap: no LOCK_NAME/FLOCKER leak to command",
          "L=unset F=unset" in leak.stdout, leak.stdout.strip())

    ## a wrapped command that itself sources lockfile does NOT self-deadlock.
    child = os.path.join(tmp, "child.sh")
    write_exec(child,
               "#!/bin/bash\n"
               "set -o errexit\n"
               "source %s\n"
               "echo CHILD_OK\n" % lockfile_sh)
    nested = run([lockfile_sh, "wE", "--", child])
    check("wrap: no self-deadlock when command sources lockfile",
          "CHILD_OK" in nested.stdout, nested.stdout.strip())

    ## usage guards: a key with no command exits non-zero and runs nothing.
    no_cmd = run([lockfile_sh, "onlykey"])
    check("wrap: key but no command -> non-zero", no_cmd.returncode != 0,
          "rc=%d" % no_cmd.returncode)

    ## collision-resistance: two keys that a naive '/'->'_slash_' substitution
    ## would alias ('a/b' vs the literal 'a_slash_b') must NOT share a lock, so
    ## a holder of one lets the other run concurrently.
    holder = bg([lockfile_sh, "cr/b", "--", "sleep", "2"])
    time.sleep(0.6)
    twin = run([lockfile_sh, "cr_slash_b", "--", "echo", "RAN"])
    check("wrap: aliasing keys do not collide", "RAN" in twin.stdout,
          "%r rc=%d" % (twin.stdout.strip(), twin.returncode))
    holder.wait(timeout=15)


def fuzz(lockfile_sh, iterations, seed, check):
    """Hammer random keys through wrap mode: a same-key contender must skip
    while a holder runs; a distinct-key contender must run."""
    rng = random.Random(seed)
    ok = True
    for _ in range(iterations):
        key = "fuzz-%d" % rng.randrange(1000)
        holder = bg([lockfile_sh, key, "--", "sleep", "1"])
        time.sleep(0.15)
        same = run([lockfile_sh, key, "--", "echo", "RAN"])
        distinct = run([lockfile_sh, key + "-x", "--", "echo", "RAN"])
        holder.wait(timeout=10)
        if "RAN" in same.stdout or same.returncode == 0:
            ok = False
            break
        if "RAN" not in distinct.stdout:
            ok = False
            break
    check("fuzz: per-key isolation over %d iterations" % iterations, ok)


def main():
    parser = argparse.ArgumentParser(description="lockfile.sh tests")
    parser.add_argument("--iterations", type=int, default=40,
                        help="fuzz iterations (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    lockfile_sh = lockfile_sh_path()
    print("lockfile.sh: %s" % lockfile_sh)
    if not os.path.exists(lockfile_sh):
        print("ERROR: lockfile.sh not found -- install helper-scripts or set "
              "LOCKFILE_SH / LOCKFILE_SH_REPO")
        return 1
    if not os.access(lockfile_sh, os.X_OK):
        print("ERROR: lockfile.sh is not executable -- wrap mode "
              "('lockfile.sh <key> -- <cmd>') re-execs it and needs +x")
        return 1

    passed = 0
    failed = 0

    def check(name, ok, detail=""):
        nonlocal passed, failed
        print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                             ("  -- " + detail) if detail and not ok else ""))
        if ok:
            passed += 1
        else:
            failed += 1

    if not args.fuzz_only:
        source_mode_tests(lockfile_sh, check)
        wrap_mode_tests(lockfile_sh, check)
    fuzz(lockfile_sh, args.iterations, args.seed, check)

    print("%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
