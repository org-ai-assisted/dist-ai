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

memfd_create policy for these leaf daemons: SIGSYS (the systemd DEFAULT for a
blocklist with no SystemCallErrorNumber, or an allowlist that omits the call) is
CORRECT. EPERM (SystemCallErrorNumber) is deliberately RESERVED for the
ESCALATORS (privleapd, systemcheck) whose seccomp filter INHERITS into fork+exec'd
children, where default SIGSYS would collaterally hard-kill a legitimate child
that touches memfd_create. A leaf daemon execs no such arbitrary children, so the
stricter SIGSYS is intended. Security is identical either way (memfd_create is
denied; the W^X bypass is closed) -- only the failure MODE differs. Do NOT "fix" a
leaf daemon by adding SystemCallErrorNumber=EPERM (see privleap
service_hardening_test.py).
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from dist_ai_seccomp import (  # noqa: E402
    effective_allowset, is_allowlist, memfd_denial, service_lines,
    service_values, syscall_filter_values)

## systemd treats true/yes/on/1 as enabled, so accept any of them, not only the
## literal 'true' (units in this rollout mix '=yes' and '=true').
TRUE_VALUES = {'true', 'yes', '1', 'on'}


def _enabled(values) -> bool:
    return bool(values) and values[-1].lower() in TRUE_VALUES


def _noexec_set(text: str) -> set:
    """Effective NoExecPaths token set under systemd reset semantics (an empty
    value clears the accumulated list; otherwise tokens accumulate)."""
    effective: set = set()
    for value in service_values(service_lines(text), 'NoExecPaths'):
        stripped = value.strip()
        if stripped == '':
            effective = set()
        else:
            effective |= set(stripped.split())
    return effective


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
    nnp_enabled = _enabled(service_values(lines, 'NoNewPrivileges'))
    out.append(('NoNewPrivileges %s' % ('enabled' if nnp else 'disabled'),
                nnp_enabled == nnp,
                'got enabled=%r, want %r' % (nnp_enabled, nnp)))
    return out


def denylist_findings(text: str, *, noexecpaths: str, nnp: bool = True) -> list:
    """Findings for a `~memfd_create` BLOCKLIST leaf unit: the common base plus
    memfd_create denied via SIGSYS (the default, NOT a soft EPERM -- see module
    docstring)."""
    out = _base_findings(text, noexecpaths, nnp)
    denial = memfd_denial(text)
    out.append(("memfd_create denied via SIGSYS (default; EPERM is reserved for "
                "escalators, not leaf daemons)", denial == 'kill',
                'memfd_denial=%r' % denial))
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
    checks.append(('soft EPERM on a leaf daemon fails (SIGSYS required)',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST + 'SystemCallErrorNumber=EPERM\n',
                       noexecpaths=_DENYLIST_OK))))
    checks.append(('wrong NoExecPaths fails',
                   not _all_ok(denylist_findings(
                       _GOOD_DENYLIST, noexecpaths='/tmp /var/tmp /dev/shm'))))
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

    bad = [name for name, ok in checks if not ok]
    if bad:
        raise AssertionError(
            'dist_ai_wx_lint self-check failed (the lint cannot reliably go '
            'red): %s' % ', '.join(bad))


if __name__ == '__main__':
    self_check()
    print('dist_ai_wx_lint self-check: OK')
