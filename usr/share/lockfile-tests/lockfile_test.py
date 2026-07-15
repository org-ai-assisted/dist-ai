#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Comprehensive test + fuzz for the flock lock helper and its per-key wrapper:
##
##   * lockfile.sh (helper-scripts) -- the atomic 'flock' FLOCKER re-exec mutex
##     a script SOURCES to self-lock. Proves: a second instance of the same
##     sourcing script SKIPS while the first holds the lock and runs once the
##     first releases; the optional LOCK_NAME override locks PER KEY (same key
##     skips, different keys run concurrently) while an unset LOCK_NAME is
##     backward-compatible (self-lock by the script's own path); a held-lock
##     skip exits non-zero; and a key with path-like characters is handled.
##
##   * locked-run (dist-encrypted) -- runs an ARBITRARY command under a per-key
##     lockfile lock. Proves: per-key skip/concurrency, exit-code propagation,
##     that the wrapped command inherits neither LOCK_NAME nor FLOCKER, that a
##     wrapped command which itself sources lockfile does NOT self-deadlock, and
##     the usage guards.
##
## A fuzz phase hammers random keys and asserts per-key isolation (same key
## serializes, distinct keys do not) against a simple in-test oracle.
##
## No root, no network. Subjects are the INSTALLED
## /usr/libexec/helper-scripts/lockfile.sh and /usr/local/bin/locked-run by
## default; set LOCKFILE_SH_REPO to a helper-scripts checkout and/or
## LOCKED_RUN_REPO to a dist-encrypted checkout to test those instead. A subject
## that is absent (or a locked-run whose /usr/local/bin/lockfile is not the
## flock version) is SKIPPED with a reason, never a false failure.
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
LOCKED_RUN_REPO = os.environ.get("LOCKED_RUN_REPO")


def lockfile_sh_path():
    ## Resolution order: an explicit LOCKFILE_SH file, then a helper-scripts
    ## checkout, then the installed canonical, then the dist-encrypted in-tree
    ## copy (same flock code). Only a FLOCK version is a valid subject -- an old
    ## PID-file lockfile is skipped (below), not falsely failed.
    direct = os.environ.get("LOCKFILE_SH")
    candidates = []
    if direct:
        candidates.append(direct)
    if LOCKFILE_SH_REPO:
        candidates.append(os.path.join(
            LOCKFILE_SH_REPO, "usr/libexec/helper-scripts/lockfile.sh"))
    candidates.append("/usr/libexec/helper-scripts/lockfile.sh")
    candidates.append("/usr/local/bin/lockfile")
    for path in candidates:
        if os.path.exists(path) and is_flock_lockfile(path):
            return path
    return None


def locked_run_path():
    if LOCKED_RUN_REPO:
        path = os.path.join(LOCKED_RUN_REPO, "usr/local/bin/locked-run")
    else:
        path = "/usr/local/bin/locked-run"
    return path if os.path.exists(path) else None


def is_flock_lockfile(path):
    """True if the given lockfile is the flock (FLOCKER) version, not the old
    PID-file one -- locked-run sources /usr/local/bin/lockfile, which must be
    the flock version for these tests to be meaningful."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return "FLOCKER" in handle.read()
    except OSError:
        return False


def write_exec(path, content):
    with open(path, "w", encoding="ascii") as handle:
        handle.write(content)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP
             | stat.S_IXOTH)


def make_source_script(tmp, lockfile_sh):
    """A tiny script that sources lockfile.sh (optional LOCK_NAME from $1) then
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


def run(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def bg(argv):
    return subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def lockfile_sh_tests(lockfile_sh, check):
    tmp = tempfile.mkdtemp(prefix="lockfile-sh-")
    src = make_source_script(tmp, lockfile_sh)

    ## 1. self-lock (no key): the 2nd instance of the same script skips while
    ## the 1st holds the lock, and exits non-zero.
    holder = bg([src, "", "2"])
    time.sleep(0.6)
    second = run([src, "", "0"])
    check("self-lock: 2nd instance skips", "LOCKED" not in second.stdout,
          second.stdout.strip())
    check("self-lock: skip exits non-zero", second.returncode != 0,
          "rc=%d" % second.returncode)
    holder.wait(timeout=15)

    ## 2. released after the holder exits -> re-acquirable.
    third = run([src, "", "0"])
    check("self-lock: re-acquirable after release", "LOCKED" in third.stdout,
          third.stdout.strip())

    ## The per-key tests below need the optional LOCK_NAME override. An older
    ## flock lockfile.sh (FLOCKER but no LOCK_NAME) still passes the self-lock
    ## tests above; skip the per-key ones there rather than false-fail.
    with open(lockfile_sh, "r", encoding="ascii", errors="replace") as handle:
        has_lock_name = "LOCK_NAME" in handle.read()
    if not has_lock_name:
        print("[SKIP] LOCK_NAME per-key tests -- this lockfile.sh has no "
              "LOCK_NAME override (older version)")
        return

    ## 3. LOCK_NAME per-key: same key skips, different key runs concurrently.
    holder = bg([src, "keyA", "2"])
    time.sleep(0.6)
    same = run([src, "keyA", "0"])
    other = run([src, "keyB", "0"])
    check("LOCK_NAME: same key skips", "LOCKED" not in same.stdout,
          same.stdout.strip())
    check("LOCK_NAME: different key runs concurrently", "LOCKED" in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## 4. a path-like key (contains '/' and '.') is handled, not a crash.
    keyed = run([src, "svc/onionv3.rend", "0"])
    check("LOCK_NAME: path-like key handled", "LOCKED" in keyed.stdout
          and keyed.returncode == 0, keyed.stdout.strip())


def locked_run_tests(locked_run, check):
    tmp = tempfile.mkdtemp(prefix="locked-run-")

    ## 5. per-key: same key skips (rc!=0, command not run), different concurrent.
    holder = bg([locked_run, "kA", "--", "sleep", "2"])
    time.sleep(0.6)
    same = run([locked_run, "kA", "--", "echo", "RAN"])
    other = run([locked_run, "kB", "--", "echo", "RAN"])
    check("locked-run: same key skips", "RAN" not in same.stdout
          and same.returncode != 0, "%r rc=%d" % (same.stdout.strip(),
                                                   same.returncode))
    check("locked-run: different key concurrent", "RAN" in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## 6. exit-code propagation.
    rc7 = run([locked_run, "kC", "--", "bash", "-c", "exit 7"])
    check("locked-run: propagates exit code", rc7.returncode == 7,
          "rc=%d" % rc7.returncode)

    ## 7. the wrapped command inherits neither LOCK_NAME nor FLOCKER.
    probe = os.path.join(tmp, "probe.sh")
    write_exec(probe,
               "#!/bin/bash\n"
               "echo \"L=${LOCK_NAME:-unset} F=${FLOCKER:-unset}\"\n")
    leak = run([locked_run, "kD", "--", probe])
    check("locked-run: no LOCK_NAME/FLOCKER leak to child",
          "L=unset F=unset" in leak.stdout, leak.stdout.strip())

    ## 8. a wrapped command that itself sources lockfile does NOT self-deadlock.
    child = os.path.join(tmp, "child.sh")
    write_exec(child,
               "#!/bin/bash\n"
               "set -o errexit\n"
               "source /usr/local/bin/lockfile\n"
               "echo CHILD_OK\n")
    nested = run([locked_run, "kE", "--", child])
    check("locked-run: no self-deadlock when child sources lockfile",
          "CHILD_OK" in nested.stdout, nested.stdout.strip())

    ## 9. usage guards.
    no_args = run([locked_run])
    no_cmd = run([locked_run, "onlykey"])
    check("locked-run: no args -> rc 2", no_args.returncode == 2,
          "rc=%d" % no_args.returncode)
    check("locked-run: key but no command -> rc 2", no_cmd.returncode == 2,
          "rc=%d" % no_cmd.returncode)


def fuzz(locked_run, iterations, seed, check):
    """Hammer random keys: a same-key contender must skip while a holder runs;
    a distinct-key contender must run. Oracle is trivial (key equality)."""
    rng = random.Random(seed)
    ok = True
    for _ in range(iterations):
        key = "fuzz-%d" % rng.randrange(1000)
        holder = bg([locked_run, key, "--", "sleep", "1"])
        time.sleep(0.15)
        same = run([locked_run, key, "--", "echo", "RAN"])
        distinct_key = key + "-x"
        distinct = run([locked_run, distinct_key, "--", "echo", "RAN"])
        holder.wait(timeout=10)
        if "RAN" in same.stdout or same.returncode == 0:
            ok = False
            break
        if "RAN" not in distinct.stdout:
            ok = False
            break
    check("fuzz: per-key isolation holds over %d iterations" % iterations, ok)


def main():
    parser = argparse.ArgumentParser(description="lockfile / locked-run tests")
    parser.add_argument("--iterations", type=int, default=40,
                        help="fuzz iterations (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    lockfile_sh = lockfile_sh_path()
    locked_run = locked_run_path()
    print("lockfile.sh: %s" % (lockfile_sh or "NOT FOUND (skipped)"))
    print("locked-run:  %s" % (locked_run or "NOT FOUND (skipped)"))

    passed = 0
    failed = 0
    skipped = 0

    def check(name, ok, detail=""):
        nonlocal passed, failed
        status = "PASS" if ok else "FAIL"
        print("[%s] %s%s" % (status, name, ("  -- " + detail) if detail
                             and not ok else ""))
        if ok:
            passed += 1
        else:
            failed += 1

    if not args.fuzz_only:
        if lockfile_sh:
            lockfile_sh_tests(lockfile_sh, check)
        else:
            print("[SKIP] lockfile.sh tests -- not found "
                  "(set LOCKFILE_SH_REPO to a helper-scripts checkout)")
            skipped += 1

    ## locked-run sources /usr/local/bin/lockfile; it must be the flock version.
    locked_run_ready = bool(locked_run) and \
        is_flock_lockfile("/usr/local/bin/lockfile")
    if locked_run and not locked_run_ready:
        print("[SKIP] locked-run tests -- /usr/local/bin/lockfile is not the "
              "flock version it sources")
        skipped += 1
    elif not locked_run:
        print("[SKIP] locked-run tests -- not found "
              "(set LOCKED_RUN_REPO to a dist-encrypted checkout)")
        skipped += 1

    if locked_run_ready and not args.fuzz_only:
        locked_run_tests(locked_run, check)
    if locked_run_ready:
        fuzz(locked_run, args.iterations, args.seed, check)

    if passed == 0 and failed == 0:
        print("no subjects available -- nothing tested (skipped=%d)" % skipped)
        return 0
    print("%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
