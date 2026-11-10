## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared W^X/NNP directive-lint engine for the Kicksecure/Whonix LEAF daemons
hardened by the W^X rollout (onion-grater, anon-ws-disable-stacked-tor,
msgcollector, vm-config-dist, desktop-config-dist, sdwdate-gui, qubes-whonix,
whonix-firewall-restarter).

Replicates privleap-tests/service_hardening_test.py's static lint, but factored
so each per-daemon lint is a short spec (its REAL unit path(s) + the directive
profile READ from that unit). Parsing is dist_ai_seccomp (the single source);
this module adds only the assertions, the present-vs-absent / exit-77 skip
discipline, and parser-fidelity self-checks.

memfd_create denial MODE (assert each unit's REAL value; the memfd= arg picks it):
- SIGSYS (the systemd DEFAULT: a blocklist with no SystemCallErrorNumber, or an
  allowlist that omits the call) is CORRECT for a daemon that NEVER calls
  memfd_create itself -- the stricter kill.
- EPERM (SystemCallErrorNumber=EPERM) is for a daemon whose OWN code, or an
  inherited child, legitimately calls memfd_create and must fail SOFT instead of
  dying. Two cases: the ESCALATORS (privleapd, systemcheck) whose filter inherits
  into fork+exec'd children, and the GUI/Wayland daemons (msgcollector, sdwdate-gui,
  livecheck) whose Qt/libwayland code maps shm draw buffers via memfd_create and
  would SIGSYS-die on first draw. EPERM keeps the W^X bypass CLOSED identically
  (memfd_create still denied) -- only the failure mode differs.
So the memfd mode is a per-daemon fact: do NOT blanket-apply either. SIGSYS for a
leaf daemon that never touches memfd_create; EPERM for one whose own/inherited
code does (see privleap service_hardening_test.py and agents/systemd-wx-hardening.md).
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from dist_ai_seccomp import (  # noqa: E402
    effective_allowset, is_allowlist, memfd_denial, service_lines,
    service_values, syscall_filter_simple, syscall_filter_values)

## systemd treats true/yes/on/1 as enabled, so accept any of them, not only the
## literal 'true' (units in this rollout mix '=yes' and '=true').
TRUE_VALUES = {'true', 'yes', '1', 'on'}


def _enabled(values) -> bool:
    return bool(values) and values[-1].lower() in TRUE_VALUES


def _path_set(text: str, key: str) -> set:
    """Effective token set of a space-list path directive (NoExecPaths /
    ExecPaths) under systemd reset semantics (an empty value clears the
    accumulated list; otherwise tokens accumulate)."""
    effective: set = set()
    for value in service_values(service_lines(text), key):
        stripped = value.strip()
        if stripped == '':
            effective = set()
        else:
            effective |= set(stripped.split())
    return effective


def _noexec_set(text: str) -> set:
    return _path_set(text, 'NoExecPaths')


def _base_findings(text: str, noexecpaths: str, nnp: bool) -> list:
    """The directives common to every hardened leaf unit. Returns a list of
    (name, ok, detail) tuples."""
    lines = service_lines(text)
    out = []
    mdwe = service_values(lines, 'MemoryDenyWriteExecute')
    out.append(('MemoryDenyWriteExecute enabled', _enabled(mdwe),
                'got %r' % mdwe))
    arch = service_values(lines, 'SystemCallArchitectures')
    out.append(('SystemCallArchitectures=native', arch[-1:] == ['native'],
                'got %r' % arch))
    lockp = service_values(lines, 'LockPersonality')
    out.append(('LockPersonality enabled', _enabled(lockp), 'got %r' % lockp))
    want = set(noexecpaths.split())
    have = _noexec_set(text)
    out.append(('NoExecPaths == %r' % sorted(want), have == want,
                'got %r' % sorted(have)))
    ## ExecPaths= nested under a NoExecPaths= subtree makes that subtree
    ## executable again (systemd.exec). A hardened unit must not carry one, or the
    ## NoExecPaths assertion above is hollow. None of these units set it.
    execpaths = _path_set(text, 'ExecPaths')
    out.append(('no ExecPaths re-opening NoExecPaths', not execpaths,
                'ExecPaths=%r' % sorted(execpaths)))
    nnp_enabled = _enabled(service_values(lines, 'NoNewPrivileges'))
    out.append(('NoNewPrivileges %s' % ('enabled' if nnp else 'disabled'),
                nnp_enabled == nnp,
                'got enabled=%r, want %r' % (nnp_enabled, nnp)))
    return out


def denylist_findings(text: str, *, noexecpaths: str, nnp: bool = True,
                      memfd: str = 'kill') -> list:
    """Findings for a `~memfd_create` BLOCKLIST unit: the common base plus
    memfd_create denied in the expected MODE.

    memfd='kill' (default): denied via SIGSYS (the systemd default, no
      SystemCallErrorNumber). Correct for a LEAF daemon that never calls
      memfd_create itself.
    memfd='soft': denied via EPERM (SystemCallErrorNumber=EPERM). Correct for a
      GUI/Wayland daemon whose OWN (or inherited Qt/libwayland) code calls
      memfd_create for shm draw buffers -- EPERM keeps the W^X bypass closed
      (still denied) while letting it fall back to shm_open and render, where the
      default SIGSYS would hard-kill it on first surface map (see module docstring)."""
    out = _base_findings(text, noexecpaths, nnp)
    denial = memfd_denial(text)
    if memfd == 'soft':
        name = ("memfd_create denied via EPERM (soft): this daemon's own "
                "Qt/Wayland code hits memfd_create, so EPERM lets it fall back to "
                "shm_open and render while keeping the W^X bypass closed")
    else:
        name = ("memfd_create denied via SIGSYS (default; EPERM is reserved for "
                "escalators and GUI/Wayland daemons whose own code hits "
                "memfd_create)")
    out.append((name, denial == memfd, 'memfd_denial=%r, want %r' % (denial, memfd)))
    return out


def allowlist_findings(text: str, *, noexecpaths: str, required_syscalls,
                       nnp: bool = True) -> list:
    """Findings for an ALLOWLIST leaf unit (onion-grater): the common base, plus
    the filter is an allowlist (no '~'), memfd_create is ABSENT from it (so it is
    SIGSYS-killed by the default-deny), and the required core syscalls are
    present (dropping one would SIGSYS-kill the daemon at runtime)."""
    out = _base_findings(text, noexecpaths, nnp)
    out.append(('SystemCallFilter is an allowlist (no "~" denylist)',
                is_allowlist(text), 'values=%r' % syscall_filter_values(text)))
    ## FAIL CLOSED unless the filter uses only PLAIN syscall tokens: a '@group'
    ## ('@ipc'/'@system-service' CONTAIN memfd_create), a per-syscall action
    ## ('read:EPERM' does not actually grant read), or a '\\'-escape all break the
    ## "memfd absent" / "required present" membership checks below, which the lint
    ## does not model. onion-grater lists syscalls explicitly, so this does not
    ## fire for it.
    out.append(('allowlist uses only plain syscall tokens (no @group / '
                'per-syscall action / escape the lint cannot model)',
                syscall_filter_simple(text),
                'values=%r' % syscall_filter_values(text)))
    allow = effective_allowset(text)
    out.append(('memfd_create absent from the allowlist (SIGSYS-killed)',
                'memfd_create' not in allow, 'memfd_create in allowset=%r'
                % ('memfd_create' in allow)))
    missing = set(required_syscalls) - allow
    out.append(('required core syscalls present', not missing,
                'missing=%r' % sorted(missing)))
    return out


def resolve_unit(repo_env_var: str, relpath: str) -> tuple:
    """(absolute unit path, repo_env_set) -- the unit under the checkout named by
    `repo_env_var` (e.g. ONION_GRATER_REPO), else the installed path ('/')."""
    repo = os.environ.get(repo_env_var, '').strip()
    base = repo if repo else '/'
    return os.path.join(base, relpath), bool(repo)


def read_text(path: str) -> str:
    with open(path, encoding='utf-8') as handle:
        return handle.read()


class Lint:
    """Accumulates one daemon's findings and renders the privleap-style verdict.

    Present-vs-absent discipline (dist-ai skip rules): a unit missing while its
    *_REPO is set is a broken subject -> FAIL (never a silent skip). With no
    *_REPO and every unit genuinely absent -> SKIP (exit 77) with a waiver.
    """

    def __init__(self, title: str):
        self.title = title
        self.failed = 0
        self.checked = 0
        self.absent_no_repo = 0

    def _emit(self, name: str, ok: bool, detail: str = '') -> None:
        if ok:
            print('  ok   %s' % name)
        else:
            self.failed += 1
            suffix = ' (%s)' % detail if detail else ''
            print('  FAIL %s%s' % (name, suffix), file=sys.stderr)

    def assert_true(self, name: str, ok: bool, detail: str = '') -> None:
        """A standalone assertion (e.g. the generator source emits the block)."""
        self._emit(name, ok, detail)

    def lint_file(self, path: str, repo_set: bool, findings_fn) -> None:
        """Lint one unit by ABSOLUTE path (e.g. a globbed autogen unit), enforcing
        the present/absent rule, then run `findings_fn(text)` and emit each
        finding. `repo_set` is whether the component *_REPO was set (a missing
        unit under a set repo is a FAIL, not a skip)."""
        if not os.path.isfile(path):
            if repo_set:
                self.failed += 1
                print('  FAIL unit missing: %s' % path, file=sys.stderr)
            else:
                self.absent_no_repo += 1
            return
        print('%s:' % path)
        for name, ok, detail in findings_fn(read_text(path)):
            self._emit(name, ok, detail)
        self.checked += 1

    def check_unit(self, repo_env_var: str, relpath: str, findings_fn) -> None:
        """Lint one unit: resolve it under the component *_REPO (else the installed
        path), enforce the present/absent rule, then run `findings_fn(text)` and
        emit each finding. `findings_fn` closes over the expected profile."""
        path, repo_set = resolve_unit(repo_env_var, relpath)
        self.lint_file(path, repo_set, findings_fn)

    def finish(self) -> int:
        if self.failed:
            print('\n%s: FAIL (%d check(s) failed)' % (self.title, self.failed),
                  file=sys.stderr)
            return 1
        if self.checked == 0 and self.absent_no_repo:
            ## style-ok: allow-skip: no *_REPO set and the unit is genuinely
            ## absent (installed-only run without the package) -- an optional
            ## target, not a broken subject.
            print('SKIP: %s -- no unit found; set the component *_REPO or '
                  'install the package.' % self.title)
            return 77
        print('\n%s: OK (%d unit(s) linted)' % (self.title, self.checked))
        return 0


## Parser-fidelity self-checks (crafted inputs; no real unit) -- prove the lint
## can go RED, so a helper regression cannot silently pass every daemon. Each
## per-daemon lint calls self_check() first (the privleap self-check idiom).
_GOOD_DENYLIST = (
    '[Service]\n'
    'MemoryDenyWriteExecute=yes\n'
    'SystemCallArchitectures=native\n'
    'LockPersonality=yes\n'
    'SystemCallFilter=~memfd_create\n'
    'NoExecPaths=/run /tmp /var/tmp /dev/shm /dev\n'
    'NoNewPrivileges=yes\n')
_GOOD_ALLOWLIST = (
    '[Service]\n'
    'MemoryDenyWriteExecute=true\n'
    'SystemCallArchitectures=native\n'
    'LockPersonality=true\n'
    'SystemCallFilter=read write execve openat\n'
    'NoExecPaths=/run /tmp /var/tmp /dev/shm\n'
    'NoNewPrivileges=true\n')
_DENYLIST_OK = '/run /tmp /var/tmp /dev/shm /dev'


def _all_ok(findings) -> bool:
    return all(ok for _n, ok, _d in findings)


def self_check() -> None:
    """Raise AssertionError if the lint helpers cannot distinguish a correct unit
    from a broken one. Run at the top of every per-daemon lint."""
    checks = []

    ## A correct denylist/allowlist unit passes cleanly.
    checks.append(('good denylist passes',
                   _all_ok(denylist_findings(_GOOD_DENYLIST,
                                             noexecpaths=_DENYLIST_OK))))
    checks.append(('good allowlist passes',
                   _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST, noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read', 'execve'}))))

    ## A missing W^X block FAILS (the whole point of the lint).
    checks.append(('missing MemoryDenyWriteExecute fails',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST.replace('MemoryDenyWriteExecute=yes\n', ''),
                       noexecpaths=_DENYLIST_OK))))
    checks.append(('soft EPERM on a kill-asserted unit fails (SIGSYS expected)',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST + 'SystemCallErrorNumber=EPERM\n',
                       noexecpaths=_DENYLIST_OK))))
    ## memfd='soft' (GUI/Wayland daemons): an EPERM unit passes, a SIGSYS one fails.
    checks.append(('EPERM unit passes when soft is asserted',
                   _all_ok(denylist_findings(
                       _GOOD_DENYLIST + 'SystemCallErrorNumber=EPERM\n',
                       noexecpaths=_DENYLIST_OK, memfd='soft'))))
    checks.append(('SIGSYS unit fails when soft is asserted (missing EPERM)',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST, noexecpaths=_DENYLIST_OK, memfd='soft'))))
    checks.append(('wrong NoExecPaths fails',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST, noexecpaths='/tmp /var/tmp /dev/shm'))))  # nosec B108 -- systemd NoExecPaths directive value, not a temp path
    checks.append(('NoNewPrivileges missing fails for a non-escalator',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST.replace('NoNewPrivileges=yes\n', ''),
                       noexecpaths=_DENYLIST_OK))))

    ## A '~' denylist token must fail the allowlist assertion (sandbox removed).
    checks.append(('a "~" token fails the allowlist check',
                   not is_allowlist(_GOOD_ALLOWLIST.replace(
                       'SystemCallFilter=read write execve openat',
                       'SystemCallFilter=~read'))))
    ## memfd_create PRESENT in the allowlist fails (it must be absent -> SIGSYS).
    checks.append(('memfd_create in the allowlist fails',
                   not _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST.replace(
                           'SystemCallFilter=read write execve openat',
                           'SystemCallFilter=read write execve openat memfd_create'),
                       noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read'}))))
    checks.append(('a dropped required syscall fails',
                   not _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST, noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read', 'clock_settime'}))))
    ## An empty SystemCallFilter= reset leaves memfd_create no longer denied.
    checks.append(('empty SystemCallFilter reset drops the memfd denial',
                   memfd_denial('[Service]\nSystemCallFilter=~memfd_create\n'
                                'SystemCallFilter=\n') == 'none'))
    ## systemd '~'-removal semantics (NOT a denylist flip): a '~' line after a
    ## positive allowlist only REMOVES syscalls, so it stays an allowlist.
    checks.append(('"~"-removal after a positive list stays an allowlist',
                   is_allowlist(_GOOD_ALLOWLIST + 'SystemCallFilter=~write\n')))
    checks.append(('"~"-removal allowlist still passes (write dropped, read kept)',
                   _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST + 'SystemCallFilter=~write\n',
                       noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read', 'execve'}))))
    ## A syscall GROUP in an allowlist fails CLOSED ('@ipc' hides memfd_create).
    checks.append(('a @group in an allowlist fails (unexpandable)',
                   not _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST.replace(
                           'SystemCallFilter=read write execve openat',
                           'SystemCallFilter=read write execve openat @ipc'),
                       noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read'}))))
    ## A per-syscall action ('read:EPERM' does not actually grant read) also fails
    ## CLOSED -- the lint does not model it.
    checks.append(('a per-syscall :action in an allowlist fails',
                   not _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST.replace(
                           'SystemCallFilter=read write execve openat',
                           'SystemCallFilter=read:EPERM write execve openat'),
                       noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'write'}))))
    ## Reset-aware: a @group DISCARDED by a later empty reset must NOT false-fail
    ## (systemd already dropped it), so a clean allowlist after the reset passes.
    checks.append(('a @group discarded by an empty reset does not false-fail',
                   _all_ok(allowlist_findings(
                       _GOOD_ALLOWLIST.replace(
                           'SystemCallFilter=read write execve openat',
                           'SystemCallFilter=@ipc\nSystemCallFilter=\n'
                           'SystemCallFilter=read write execve openat'),
                       noexecpaths='/run /tmp /var/tmp /dev/shm',
                       required_syscalls={'read', 'execve'}))))
    ## A positive @group re-allowing memfd_create after '~memfd_create' fails the
    ## denylist (memfd_denial must report it as no longer denied).
    checks.append(('a positive @group re-allowing memfd fails the denylist',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST + 'SystemCallFilter=@ipc\n',
                       noexecpaths=_DENYLIST_OK))))
    ## ExecPaths= re-opening a NoExecPaths subtree fails.
    checks.append(('ExecPaths re-opening NoExecPaths fails',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST + 'ExecPaths=/tmp/payload\n',
                       noexecpaths=_DENYLIST_OK))))

    bad = [name for name, ok in checks if not ok]
    if bad:
        raise AssertionError(
            'dist_ai_wx_lint self-check failed (the lint cannot reliably go '
            'red): %s' % ', '.join(bad))


if __name__ == '__main__':
    self_check()
    print('dist_ai_wx_lint self-check: OK')
