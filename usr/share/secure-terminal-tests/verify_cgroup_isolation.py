#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Live proof that per-tab resource_isolation actually CONTAINS a runaway on a
real cgroup v2 host -- what the fake-tree unit tests cannot show. Needs delegated
memory+pids (a modern systemd user session); prints why and exits 77 when that is
absent, so it is EVIDENCE for the sandbox, not a wired gate.

Proves, against real kernel cgroups:
  1. create_tab writes limits a real cgroup ACCEPTS (pids.max, memory.max,
     memory.oom.group) -- a fake dir cannot validate these.
  2. a child placed via open_procs/place_pid actually lands in the tab cgroup.
  3. pids.max is ENFORCED: a fork past the ceiling gets EAGAIN, bounded to the tab.
  4. memory.max (+ oom.group, swap denied) is ENFORCED: an over-cap allocation is
     contained (OOM-killed as a unit, or refused) while THIS process -- a sibling --
     survives.

Re-runnable: every probe cgroup is drained and removed, and a leftover from a
crashed prior run is cleared before reuse (never a second-run FileExistsError).
"""

import os
import sys
import time

from secure_terminal import resource_isolation as ri

_fail = 0


def ok(cond, msg):
    global _fail
    print('ok   %s' % msg if cond else 'FAIL: %s' % msg)
    if not cond:
        _fail += 1


def _write(path, text):
    with open(path, 'w', encoding='ascii') as handle:
        handle.write(text)


def _read(path):
    with open(path, encoding='ascii') as handle:
        return handle.read().strip()


def _procs(path):
    try:
        return _read(os.path.join(path, 'cgroup.procs')).split()
    except OSError:
        return []


def _drain_and_remove(path):
    """Wait for a cgroup to empty (killed children leave asynchronously), then
    remove it, so a later run never trips over a leftover populated cgroup."""
    for _ in range(500):
        if not _procs(path):
            break
        time.sleep(0.02)
    try:
        os.rmdir(path)
    except OSError:
        pass                          # already gone, or still populated -> leave it


def _fresh_cgroup(parent, name):
    """A clean child cgroup, clearing any leftover from a crashed prior run first."""
    path = os.path.join(parent, name)
    _drain_and_remove(path)
    os.makedirs(path, exist_ok=True)
    return path


base = ri.base_setup()
if base is None:
    print('secure-terminal-tests(cgroup): SKIP -- no cgroup v2 memory+pids '
          'delegation on this host')
    sys.exit(77)

# 1 + 2: create_tab on a REAL cgroup, and a child lands in it -------------------
tab = ri.create_tab(base, 'verify-place')
ok(tab is not None, 'create_tab: a real cgroup accepts the limits')
ok(_read(os.path.join(tab, 'pids.max')) == str(ri.PIDS_MAX),
   'create_tab: pids.max is set on the real cgroup')
ok(_read(os.path.join(tab, 'memory.oom.group')) == '1',
   'create_tab: memory.oom.group is set on the real cgroup')
fd = ri.open_procs(tab)
pid = os.fork()
if pid == 0:                                  # child: join the cgroup, then idle
    ri.place_pid(fd, os.getpid())
    time.sleep(30)
    os._exit(0)
os.close(fd)
placed = []
for _ in range(500):                          # poll -- no fixed sleep, no sched race
    placed = _procs(tab)
    if str(pid) in placed:
        break
    time.sleep(0.02)
ok(str(pid) in placed, 'place_pid: the child is a member of the tab cgroup')
os.kill(pid, 9)
os.waitpid(pid, 0)
_drain_and_remove(tab)

# 3: pids.max is ENFORCED -- a fork past a tiny ceiling gets EAGAIN -------------
capped = _fresh_cgroup(base, 'verify-pids')
_write(os.path.join(capped, 'pids.max'), '3')   # tiny ceiling for the proof
fd = ri.open_procs(capped)
r, w = os.pipe()
pid = os.fork()
if pid == 0:                                  # child in the capped cgroup
    ri.place_pid(fd, os.getpid())
    os.close(r)
    hit_limit = False
    kids = []
    for _ in range(20):                       # try to blow past pids.max=3
        try:
            k = os.fork()
        except OSError:
            hit_limit = True                  # EAGAIN: the ceiling held
            break
        if k == 0:
            time.sleep(5)
            os._exit(0)
        kids.append(k)
    os.write(w, b'1' if hit_limit else b'0')
    for k in kids:
        os.kill(k, 9)
    os._exit(0)
os.close(fd)
os.close(w)
verdict = os.read(r, 1)
os.close(r)
os.waitpid(pid, 0)
ok(verdict == b'1',
   'pids.max: a fork bomb hits EAGAIN at the tab ceiling (contained, not the host)')
_drain_and_remove(capped)

# 4: memory.max + oom.group (swap denied) is ENFORCED --------------------------
memcg = _fresh_cgroup(base, 'verify-mem')
# Cap well above the Python interpreter baseline (a sub-baseline cap would OOM the
# child before it allocates), far below the allocation the child attempts.
_write(os.path.join(memcg, 'memory.max'), str(128 * 1024 * 1024))   # 128 MiB cap
_write(os.path.join(memcg, 'memory.oom.group'), '1')
# Deny swap, else the runaway is paged out past the cap instead of hitting the OOM
# killer (and thrashes the host). Best-effort: absent without swap accounting.
try:
    _write(os.path.join(memcg, 'memory.swap.max'), '0')
except OSError:
    pass                              # no swap controller -> memory.max alone caps RAM
fd = ri.open_procs(memcg)
pid = os.fork()
if pid == 0:                                  # child: allocate far past the cap
    ri.place_pid(fd, os.getpid())
    blob = []
    try:
        for _ in range(256):
            blob.append(bytearray(16 * 1024 * 1024))   # 16 MiB steps, touched
    except MemoryError:
        os._exit(42)                          # allocation refused -> also contained
    os._exit(0)
os.close(fd)
_, status = os.waitpid(pid, 0)
# Contained either way: OOM-killed as a unit (SIGKILL) OR the allocation refused
# (MemoryError -> exit 42). A clean exit 0 means the runaway was NOT contained.
killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
refused = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 42
completed = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
ok(killed or refused,
   'memory.max: the over-cap child is contained (OOM-killed as a unit, or refused)')
ok(not completed, 'memory.max: the runaway did not complete its allocation')
_drain_and_remove(memcg)

print('secure-terminal-tests(cgroup): all passed' if not _fail else
      'secure-terminal-tests(cgroup): %d failed' % _fail)
sys.exit(1 if _fail else 0)
