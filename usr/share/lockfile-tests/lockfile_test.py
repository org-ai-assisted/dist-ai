#!/usr/bin/python3 -Bsu

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
##   * INLINE-SAFETY -- some builds (the dist-installer-cli standalone generator)
##     paste lockfile.sh's BODY verbatim into a host script. Inlined, its top
##     level runs with BASH_SOURCE[0]==$0, which must NOT mis-fire wrap mode and
##     eat the host's own first argument; the host must still self-lock.
##
##   * NO-FALLBACK (by design) -- the lock dir lives ONLY under the per-user
##     runtime dir (XDG_RUNTIME_DIR, else /run/user/$EUID), owned by $EUID and not
##     a symlink. There is NO /tmp, 1777-dir or ${HOME}/.cache fallback: such a
##     fallback would reopen the TOCTOU + pre-login/post-login double-run hole the
##     comment in lockfile.sh spells out. When the runtime dir is absent, symlinked
##     or not owned, the helper HARD-EXITS 'no per-user runtime dir' and creates NO
##     lock anywhere -- never silently relocating the lock. These legs are the
##     canary: reintroducing a cache/tmp fallback, or following a symlinked runtime
##     dir, flips them RED.
##
## A fuzz phase hammers random keys through wrap mode and asserts per-key
## isolation against a key-equality oracle.
##
## No root, no network. The subject is the installed
## /usr/libexec/helper-scripts/lockfile.sh; set LOCKFILE_SH to an explicit file
## or LOCKFILE_SH_REPO to a helper-scripts checkout to test that instead. An
## absent lockfile.sh exits 77 (SKIP); a present but feature-incomplete one
## FAILS.
##
## Usage: lockfile_test.py [--iterations N] [--seed N] [--fuzz-only]

import argparse
import os
import pwd
import random
import select
import stat
import subprocess
import sys
import tempfile
import time

LOCKFILE_SH_REPO = os.environ.get('LOCKFILE_SH_REPO')


def lockfile_sh_path():
    direct = os.environ.get('LOCKFILE_SH')
    if direct:
        return direct
    if LOCKFILE_SH_REPO:
        return os.path.join(LOCKFILE_SH_REPO,
                            'usr/libexec/helper-scripts/lockfile.sh')
    return '/usr/libexec/helper-scripts/lockfile.sh'


def write_exec(path, content):
    with open(path, 'w', encoding='ascii') as handle:
        handle.write(content)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP
             | stat.S_IXOTH)


def run(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def bg(argv):
    return subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def wait_for_locked(proc, timeout=10):
    """Read PROC's stdout until a 'LOCKED' token (the holder acquired the lock) or
    EOF (it exited first). Returns True iff LOCKED was seen -- a deterministic sync
    point for 'now contend' tests, unlike a fixed sleep that races a loaded host.

    Hard-bounded by TIMEOUT even if the holder stalls WITHOUT writing a newline (a
    hung 'source lockfile.sh' -- the very regression this suite guards): select()
    caps every wait and os.read() on the raw fd never blocks past the deadline, so
    a blocking readline() can no longer hang the whole suite. On timeout the stalled
    holder is killed so it cannot leak."""
    deadline = time.monotonic() + timeout
    fd = proc.stdout.fileno()
    buf = b''
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            return False
        if not select.select([fd], [], [], remaining)[0]:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            return False
        buf += chunk
        if b'LOCKED' in buf:
            return True


def make_source_script(tmp, lockfile_sh):
    """A script that sources lockfile.sh (optional LOCK_NAME from $1), then
    prints LOCKED and sleeps $2 -- run concurrently to observe the lock."""
    path = os.path.join(tmp, 'src_lock.sh')
    write_exec(path,
               '#!/bin/bash\n'
               'set -o errexit\n'
               'set -o nounset\n'
               "if [ -n \"${1:-}\" ]; then LOCK_NAME=\"$1\"; fi\n"
               'source %s\n'
               'echo LOCKED\n'
               "sleep \"${2:-0}\"\n" % lockfile_sh)
    return path


def source_mode_tests(lockfile_sh, check):
    tmp = tempfile.mkdtemp(prefix='lockfile-src-')
    src = make_source_script(tmp, lockfile_sh)

    ## self-lock (no key): 2nd instance skips (non-zero) while the 1st holds it.
    ## Assert the flock 'failed to get lock' signal (the --verbose probe emits it to
    ## stderr on genuine contention), not merely 'no LOCKED + non-zero' -- an unrelated
    ## abort (e.g. a broken lock dir) would otherwise false-pass as a skip. Sync on the
    ## holder's LOCKED line (wait_for_locked), not a fixed sleep that races a loaded host.
    holder = bg([src, '', '2'])
    locked = wait_for_locked(holder)
    second = run([src, '', '0'])
    combined = second.stdout + second.stderr
    check('source: self-lock 2nd instance skips',
          locked and 'LOCKED' not in second.stdout
          and 'failed to get lock' in combined,
          'locked=%s %r' % (locked, combined.strip()))
    check('source: skip exits non-zero', second.returncode != 0,
          'rc=%d' % second.returncode)
    holder.wait(timeout=15)
    third = run([src, '', '0'])
    check('source: re-acquirable after release', 'LOCKED' in third.stdout,
          third.stdout.strip())

    ## LOCK_NAME per-key: same key skips, different key runs concurrently.
    holder = bg([src, 'keyA', '2'])
    time.sleep(0.6)
    same = run([src, 'keyA', '0'])
    other = run([src, 'keyB', '0'])
    check('source: LOCK_NAME same key skips', 'LOCKED' not in same.stdout,
          same.stdout.strip())
    check('source: LOCK_NAME different key concurrent', 'LOCKED' in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## a path-like key (contains '/' and '.') is handled.
    keyed = run([src, 'svc/onionv3.rend', '0'])
    check('source: path-like key handled',
          'LOCKED' in keyed.stdout and keyed.returncode == 0,
          keyed.stdout.strip())


def wrap_mode_tests(lockfile_sh, check):
    tmp = tempfile.mkdtemp(prefix='lockfile-wrap-')

    ## per-key: same key skips (rc!=0, command not run), different concurrent.
    ## Sync on the held command's LOCKED line (wait_for_locked), not a fixed sleep that
    ## races a loaded host: the wrapped command prints LOCKED once it runs under the lock.
    holder = bg([lockfile_sh, 'wA', '--', 'bash', '-c', 'echo LOCKED; sleep 2'])
    locked = wait_for_locked(holder)
    same = run([lockfile_sh, 'wA', '--', 'echo', 'RAN'])
    other = run([lockfile_sh, 'wB', '--', 'echo', 'RAN'])
    ## Require the flock 'failed to get lock' signal (the --verbose probe emits it on
    ## contention), not just 'no RAN + non-zero' which an unrelated abort also yields.
    check('wrap: same key skips', locked and 'RAN' not in same.stdout
          and same.returncode != 0
          and 'failed to get lock' in (same.stdout + same.stderr),
          'locked=%s %r rc=%d' % (locked, (same.stdout + same.stderr).strip(),
                                  same.returncode))
    check('wrap: different key concurrent', 'RAN' in other.stdout,
          other.stdout.strip())
    holder.wait(timeout=15)

    ## exit-code propagation.
    rc7 = run([lockfile_sh, 'wC', '--', 'bash', '-c', 'exit 7'])
    check('wrap: propagates exit code', rc7.returncode == 7,
          'rc=%d' % rc7.returncode)

    ## the wrapped command inherits neither LOCK_NAME nor FLOCKER.
    probe = os.path.join(tmp, 'probe.sh')
    write_exec(probe,
               '#!/bin/bash\n'
               "echo \"L=${LOCK_NAME:-unset} F=${FLOCKER:-unset}\"\n")
    leak = run([lockfile_sh, 'wD', '--', probe])
    check('wrap: no LOCK_NAME/FLOCKER leak to command',
          'L=unset F=unset' in leak.stdout, leak.stdout.strip())

    ## a wrapped command that itself sources lockfile does NOT self-deadlock.
    child = os.path.join(tmp, 'child.sh')
    write_exec(child,
               '#!/bin/bash\n'
               'set -o errexit\n'
               'source %s\n'
               'echo CHILD_OK\n' % lockfile_sh)
    nested = run([lockfile_sh, 'wE', '--', child])
    check('wrap: no self-deadlock when command sources lockfile',
          'CHILD_OK' in nested.stdout, nested.stdout.strip())

    ## usage guards: a key with no command exits non-zero and runs nothing.
    no_cmd = run([lockfile_sh, 'onlykey'])
    check('wrap: key but no command -> non-zero', no_cmd.returncode != 0,
          'rc=%d' % no_cmd.returncode)

    ## collision-resistance: two keys that a naive '/'->'_slash_' substitution
    ## would alias ('a/b' vs the literal 'a_slash_b') must NOT share a lock, so
    ## a holder of one lets the other run concurrently.
    holder = bg([lockfile_sh, 'cr/b', '--', 'sleep', '2'])
    time.sleep(0.6)
    twin = run([lockfile_sh, 'cr_slash_b', '--', 'echo', 'RAN'])
    check('wrap: aliasing keys do not collide', 'RAN' in twin.stdout,
          '%r rc=%d' % (twin.stdout.strip(), twin.returncode))
    holder.wait(timeout=15)


def make_inlined_host(tmp, lockfile_sh):
    """Mimic build-dist-installer-cli: paste lockfile.sh's BODY (minus its
    shebang) verbatim into a host script, under a fixed LOCK_NAME, then the host's
    own 'main'. Reads the CURRENT lockfile.sh text, so no drift. The host takes
    its own args ($1 a stand-in installer flag, $2 a hold time) -- $1 must NOT be
    mis-read as a wrap-mode lock key once inlined."""
    body = open(lockfile_sh, encoding='ascii').read().splitlines()
    if body and body[0].startswith('#!'):
        body = body[1:]
    path = os.path.join(tmp, 'inlined_host.sh')
    write_exec(path,
               '#!/bin/bash\n'
               'set -o errexit\n'
               'set -o nounset\n'
               'export LOCK_NAME="inlined-host-key"\n'
               + '\n'.join(body) + '\n'
               'echo LOCKED\n'
               "sleep \"${2:-0}\"\n")
    return path


def inline_safety_tests(lockfile_sh, check):
    """build-dist-installer-cli inlines lockfile.sh's body into the
    dist-installer-cli standalone. Inlined, BASH_SOURCE[0]==$0 at the host's top
    level: wrap mode must stay off (not eat the host's $1) and the host must still
    self-lock. Pre-fix, an inlined host aborted on ANY argument."""
    tmp = tempfile.mkdtemp(prefix='lockfile-inline-')
    runtime = os.path.join(tmp, 'xdg')
    os.mkdir(runtime, 0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=runtime)
    host = make_inlined_host(tmp, lockfile_sh)

    def hrun(args):
        return subprocess.run([host] + args, capture_output=True, text=True,
                              timeout=30, env=env)

    ## 1) a host invoked WITH an argument self-locks instead of mis-firing wrap
    ##    mode: it reaches LOCKED and exits 0 (pre-fix: aborts, no LOCKED).
    first = hrun(['installer-flag', '0'])
    check('inline: host argument does not mis-fire wrap mode',
          'LOCKED' in first.stdout and first.returncode == 0,
          '%r rc=%d' % ((first.stdout + first.stderr).strip()[:120],
                        first.returncode))

    ## 2) the inlined self-lock still mutually excludes: a 2nd instance skips
    ##    while the 1st holds the lock. Assert the flock failure message, not just
    ##    a non-zero exit -- a wrap-mode mis-fire also exits non-zero with no
    ##    LOCKED, so a bare rc check would pass for the wrong reason.
    holder = subprocess.Popen([host, 'installer-flag', '10'],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, env=env)
    locked = wait_for_locked(holder)
    second = hrun(['installer-flag', '0'])
    check('inline: 2nd inlined instance skips while 1st holds',
          locked and 'LOCKED' not in second.stdout and second.returncode != 0
          and 'failed to get lock' in (second.stdout + second.stderr),
          'locked=%s %r rc=%d' % (locked,
                                  (second.stdout + second.stderr).strip(),
                                  second.returncode))
    holder.terminate()
    holder.wait(timeout=10)


def security_tests(lockfile_sh, check):
    """The lock directory must live under the caller's per-user runtime dir
    (XDG_RUNTIME_DIR), never /tmp, and a symlinked lock dir must be refused --
    the /tmp-symlink attack class the per-user /run design closes."""
    ## 1) honors XDG_RUNTIME_DIR: the lock dir is <runtime>/flocker-temp-folder,
    ##    not /tmp.
    tmp = tempfile.mkdtemp(prefix='lockfile-sec-')
    src = make_source_script(tmp, lockfile_sh)
    runtime = os.path.join(tmp, 'xdg')
    os.mkdir(runtime, 0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=runtime)
    res = subprocess.run([src, '', '0'], capture_output=True, text=True,
                         timeout=30, env=env)
    lockdir = os.path.join(runtime, 'flocker-temp-folder')
    check('security: lock dir under XDG_RUNTIME_DIR, not /tmp',
          'LOCKED' in res.stdout and os.path.isdir(lockdir),
          '%r isdir=%s' % (res.stdout.strip(), os.path.isdir(lockdir)))

    ## 2) a symlinked lock dir is refused (mkdir -p would otherwise follow it).
    tmp2 = tempfile.mkdtemp(prefix='lockfile-sec2-')
    src2 = make_source_script(tmp2, lockfile_sh)
    runtime2 = os.path.join(tmp2, 'xdg')
    os.mkdir(runtime2, 0o700)
    evil = os.path.join(tmp2, 'evil')
    os.mkdir(evil)
    os.symlink(evil, os.path.join(runtime2, 'flocker-temp-folder'))
    env2 = dict(os.environ, XDG_RUNTIME_DIR=runtime2)
    res2 = subprocess.run([src2, '', '0'], capture_output=True, text=True,
                          timeout=30, env=env2)
    combined = (res2.stdout + res2.stderr).lower()
    check('security: symlinked lock dir refused',
          'LOCKED' not in res2.stdout and res2.returncode != 0
          and 'symlink' in combined,
          '%r rc=%d' % ((res2.stdout + res2.stderr).strip()[:120],
                        res2.returncode))


def no_fallback_tests(lockfile_sh, check):
    """By design lockfile.sh has NO fallback outside the per-user runtime dir -- no
    /tmp, no 1777 dir, no ${HOME}/.cache (lockfile.sh's own comment spells out the
    TOCTOU + pre-login/post-login double-run concurrency reasons). When the runtime
    dir is unusable the helper HARD-EXITS 'no per-user runtime dir' and creates NO
    lock anywhere. These legs are the canary for that guarantee: a build that
    reintroduces an XDG_CACHE_HOME (or /tmp) fallback, or follows a symlinked runtime
    dir, flips them RED."""
    ## 1) runtime dir absent -> hard exit, NO lock created under the cache dir.
    ##    XDG_CACHE_HOME + HOME are redirected into the temp tree so a (wrongly
    ##    reintroduced) cache fallback would materialise a lock dir HERE and be
    ##    caught, while the real ~/.cache is never touched.
    tmp = tempfile.mkdtemp(prefix='lockfile-nofb-')
    src = make_source_script(tmp, lockfile_sh)
    cache = os.path.join(tmp, 'cache')
    os.mkdir(cache, 0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=os.path.join(tmp, 'absent'),
               XDG_CACHE_HOME=cache, HOME=tmp)
    res = subprocess.run([src, '', '0'], capture_output=True, text=True,
                         timeout=30, env=env)
    combined = (res.stdout + res.stderr).lower()
    cache_lock = os.path.exists(os.path.join(cache, 'flocker-temp-folder'))
    check('no-fallback: absent runtime dir hard-exits, no cache lock',
          'LOCKED' not in res.stdout and res.returncode != 0
          and 'no per-user runtime dir' in combined and not cache_lock,
          '%r rc=%d cache_lock=%s' % ((res.stdout + res.stderr).strip()[:120],
                                      res.returncode, cache_lock))

    ## 2) a symlinked runtime dir is refused by the '! -L' gate AND not followed:
    ##    the symlink target dir stays empty (no lock dir created inside it). A stub
    ##    that followed the symlink would create flocker-temp-folder in the target.
    tmp2 = tempfile.mkdtemp(prefix='lockfile-nofb2-')
    src2 = make_source_script(tmp2, lockfile_sh)
    target = os.path.join(tmp2, 'target')
    os.mkdir(target)
    runtime2 = os.path.join(tmp2, 'runtime-link')
    os.symlink(target, runtime2)
    env2 = dict(os.environ, XDG_RUNTIME_DIR=runtime2,
                XDG_CACHE_HOME=os.path.join(tmp2, 'cache'), HOME=tmp2)
    res2 = subprocess.run([src2, '', '0'], capture_output=True, text=True,
                          timeout=30, env=env2)
    combined2 = (res2.stdout + res2.stderr).lower()
    target_entries = os.listdir(target)
    check('no-fallback: symlinked runtime dir refused, not followed',
          'LOCKED' not in res2.stdout and res2.returncode != 0
          and 'no per-user runtime dir' in combined2 and target_entries == [],
          '%r rc=%d target=%r' % ((res2.stdout + res2.stderr).strip()[:120],
                                  res2.returncode, target_entries))

    ## 3) a runtime dir that exists but is NOT owned by the caller (an inherited
    ##    XDG_RUNTIME_DIR under 'sudo -u') is refused by the '-O' gate -- it must
    ##    hard-exit, NOT relocate the lock to the cache dir. This closes the TOCTOU
    ##    hole of trusting a dir another uid controls. The precondition is a dir the
    ##    EUID does NOT own: as root (root owns /usr, so a hard-coded '/usr' would
    ##    make '-O' TRUE and skip the leg) create a controlled dir and chown it to
    ##    'nobody'; unprivileged, a stable root-owned system dir already qualifies.
    tmp3 = tempfile.mkdtemp(prefix='lockfile-nofb3-')
    src3 = make_source_script(tmp3, lockfile_sh)
    cache3 = os.path.join(tmp3, 'cache')
    os.mkdir(cache3, 0o700)
    if os.geteuid() == 0:
        nobody = pwd.getpwnam('nobody')
        runtime3 = os.path.join(tmp3, 'notowned')
        os.mkdir(runtime3, 0o755)
        os.chown(runtime3, nobody.pw_uid, nobody.pw_gid)
    else:
        runtime3 = '/usr'
    env3 = dict(os.environ, XDG_RUNTIME_DIR=runtime3,
                XDG_CACHE_HOME=cache3, HOME=tmp3)
    res3 = subprocess.run([src3, '', '0'], capture_output=True, text=True,
                          timeout=30, env=env3)
    combined3 = (res3.stdout + res3.stderr).lower()
    cache3_lock = os.path.exists(os.path.join(cache3, 'flocker-temp-folder'))
    check('no-fallback: non-owned runtime dir hard-exits, no cache lock',
          'LOCKED' not in res3.stdout and res3.returncode != 0
          and 'no per-user runtime dir' in combined3 and not cache3_lock,
          '%r rc=%d cache_lock=%s' % ((res3.stdout + res3.stderr).strip()[:120],
                                      res3.returncode, cache3_lock))

    ## 4) unset HOME under the caller's 'set -o nounset' must still reach the clean
    ##    'no per-user runtime dir' exit, NOT abort with 'HOME: unbound variable':
    ##    the helper has no cache fallback, so it must never dereference HOME.
    tmp4 = tempfile.mkdtemp(prefix='lockfile-nofb4-')
    src4 = make_source_script(tmp4, lockfile_sh)
    env4 = dict(os.environ, XDG_RUNTIME_DIR=os.path.join(tmp4, 'absent'))
    env4.pop('XDG_CACHE_HOME', None)
    env4.pop('HOME', None)
    res4 = subprocess.run([src4, '', '0'], capture_output=True, text=True,
                          timeout=30, env=env4)
    combined4 = (res4.stdout + res4.stderr).lower()
    check('no-fallback: unset HOME under nounset errors cleanly',
          'LOCKED' not in res4.stdout and res4.returncode != 0
          and 'unbound variable' not in combined4
          and 'no per-user runtime dir' in combined4,
          '%r rc=%d' % ((res4.stdout + res4.stderr).strip()[:120],
                        res4.returncode))


def fuzz(lockfile_sh, iterations, seed, check):
    """Hammer random keys through wrap mode: a same-key contender must skip
    while a holder runs; a distinct-key contender must run."""
    rng = random.Random(seed)
    ok = True
    for _ in range(iterations):
        key = 'fuzz-%d' % rng.randrange(1000)
        holder = bg([lockfile_sh, key, '--', 'sleep', '1'])
        time.sleep(0.15)
        same = run([lockfile_sh, key, '--', 'echo', 'RAN'])
        distinct = run([lockfile_sh, key + '-x', '--', 'echo', 'RAN'])
        holder.wait(timeout=10)
        if 'RAN' in same.stdout or same.returncode == 0:
            ok = False
            break
        if 'RAN' not in distinct.stdout:
            ok = False
            break
    check('fuzz: per-key isolation over %d iterations' % iterations, ok)


def main():
    parser = argparse.ArgumentParser(description='lockfile.sh tests')
    parser.add_argument('--iterations', type=int, default=40,
                        help='fuzz iterations (default: %(default)s)')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--fuzz-only', action='store_true')
    args = parser.parse_args()

    lockfile_sh = lockfile_sh_path()
    print('lockfile.sh: %s' % lockfile_sh)
    if not os.path.exists(lockfile_sh):
        # lockfile.sh is a REQUIRED subject: its absence is an environment bug,
        # not an optional target. A required dep that vanished must fail LOUD
        # (exit 1), never skip -- a silent 77 would stop gating unnoticed.
        print('FATAL: lockfile.sh not found -- install helper-scripts or set '
              'LOCKFILE_SH / LOCKFILE_SH_REPO', file=sys.stderr)
        return 1
    if not os.access(lockfile_sh, os.X_OK):
        print('ERROR: lockfile.sh is not executable -- wrap mode '
              "('lockfile.sh <key> -- <cmd>') re-execs it and needs +x")
        return 1

    passed = 0
    failed = 0

    def check(name, ok, detail=''):
        nonlocal passed, failed
        print('[%s] %s%s' % ('PASS' if ok else 'FAIL', name,
                             ('  -- ' + detail) if detail and not ok else ''))
        if ok:
            passed += 1
        else:
            failed += 1

    if not args.fuzz_only:
        source_mode_tests(lockfile_sh, check)
        wrap_mode_tests(lockfile_sh, check)
        inline_safety_tests(lockfile_sh, check)
        security_tests(lockfile_sh, check)
        no_fallback_tests(lockfile_sh, check)
    fuzz(lockfile_sh, args.iterations, args.seed, check)

    print('%d passed, %d failed' % (passed, failed))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
