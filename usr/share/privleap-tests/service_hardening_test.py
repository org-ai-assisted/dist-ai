#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of privleapd.service's W^X hardening -- runs in the core lane (no
root, no systemd), complementing the runtime inheritance proof in e2e_systemd.py.

Two regressions it locks:

  * NoNewPrivileges must NOT be declared yes. privleapd is a root service WITH
    CAP_SYS_ADMIN, so systemd installs the seccomp filter via that capability and
    does NOT force PR_SET_NO_NEW_PRIVS=1 -- NoNewPrivileges=false is HONORED
    (NoNewPrivs=0) and intentional: an escalated action may still exec a SUID
    helper, matching the sudo-like role. Flipping it to yes would silently break
    SUID/file-cap actions. (A user-scope service, lacking CAP_SYS_ADMIN, would
    have no_new_privs forced on regardless.)

  * memfd_create must be denied via a SOFT errno (SystemCallErrorNumber=EPERM),
    never the default SIGSYS kill. The filter inherits into every escalated
    action (plain fork+exec via shim.py); with the default action a denied
    memfd_create SIGSYS-KILLS the action (exit 159). EPERM blocks the W^X memfd
    bypass identically while letting an action fail soft.

The memfd check models systemd's effective-policy semantics (memfd_denial):
[Service]-section only, SystemCallFilter= empty-reset, a per-syscall ':' action
that overrides the global SystemCallErrorNumber, and errno validity -- a lint
fooled by any of those would report a confident wrong pass. That model is the
SINGLE source dist_ai_seccomp, imported identically by
systemcheck-tests/test_wx_seccomp_filter.py (no hand-synced copy to drift).

Resolves the unit via PRIVLEAP_REPO (dist-ai/CLAUDE.md), else the installed path.
"""

import os
import sys

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
## The seccomp policy model (memfd_denial / errno_is_soft / the directive parser) is a
## SINGLE source shared with systemcheck-tests, shipped in dist-ai's dist-packages tree.
## Insert it relative to this file (the dm_test_results idiom) so both suites import the
## same code -- no hand-synced copy to drift.
_LIB: str = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from pl_testlib import Results  # noqa: E402
from dist_ai_seccomp import (  # noqa: E402
    errno_is_soft, memfd_denial, service_lines, service_values)

TRUE_VALUES = {'true', 'yes', '1', 'on'}


def service_path() -> str:
    repo = os.environ.get('PRIVLEAP_REPO')
    base = repo if repo else '/'
    return os.path.join(
        base, 'usr', 'lib', 'systemd', 'system', 'privleapd.service')


def main() -> int:
    path = service_path()
    if not os.path.isfile(path):
        if os.environ.get('PRIVLEAP_REPO'):
            ## A real checkout always ships the unit; its absence is a broken
            ## subject, not an optional target -- FAIL, never a silent skip.
            print(f"FAIL: PRIVLEAP_REPO set but {path} is missing.",
                  file=sys.stderr)
            return 1
        ## style-ok: allow-skip: installed-only run without PRIVLEAP_REPO and no
        ## privleapd installed -- an optional target genuinely absent.
        print(f"SKIP: {path} not found -- set PRIVLEAP_REPO or install privleap.")
        return 77

    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    lines = service_lines(text)
    results = Results()

    ## Parser-fidelity self-checks (crafted inputs; no unit needed) -- guard the
    ## directive parser the lint below trusts against a silent regression.
    results.check('service_values tolerates whitespace around =',
                  service_values(['MemoryDenyWriteExecute = yes'],
                                 'MemoryDenyWriteExecute') == ['yes'])
    results.check('errno_is_soft rejects EINTR (retryable -> spins, not a soft deny)',
                  not errno_is_soft('EINTR'))
    results.check('errno_is_soft rejects a bogus errno name (systemd keeps the kill)',
                  not errno_is_soft('EBOGUS'))
    ## A REAL errno whose name carries a digit (E2BIG) is accepted by systemd -- the
    ## denied call returns that errno, it does not SIGSYS. .isdigit() is False (it has
    ## letters), so it must be validated by name, never mis-classified as a kill.
    results.check('errno_is_soft accepts a digit-in-name real errno (E2BIG -> soft)',
                  errno_is_soft('E2BIG'))
    results.check('errno_is_soft accepts a numeric errno in range (13 -> soft)',
                  errno_is_soft('13'))
    ## errno NAME aliases: errno.errorcode keeps only one name per number, dropping the alias of
    ## each pair (EOPNOTSUPP/ENOTSUP, EDEADLOCK/EDEADLK) which systemd accepts. The valid set must
    ## be built from every errno.E* constant, else a unit using the dropped alias is mis-reported kill.
    results.check('errno_is_soft accepts errno name aliases (EOPNOTSUPP/EDEADLOCK -> soft)',
                  errno_is_soft('EOPNOTSUPP') and errno_is_soft('EDEADLOCK'))
    results.check('memfd_denial honors a later positive re-allow of the syscall',
                  memfd_denial('[Service]\nSystemCallFilter=~memfd_create:EPERM\n'
                               'SystemCallFilter=memfd_create\n') == 'none')
    results.check('memfd_denial ignores a wrong-case [service] header',
                  memfd_denial('[service]\nSystemCallFilter=~memfd_create:EPERM\n')
                  == 'none')

    ## Hardening intact (section-aware: directives outside [Service] are inert).
    ## systemd treats true/yes/on/1 as enabled, so accept any of them (TRUE_VALUES),
    ## not only the literal 'true'.
    mdwe = service_values(lines, 'MemoryDenyWriteExecute')
    results.check('MemoryDenyWriteExecute enabled',
                  bool(mdwe) and mdwe[-1].lower() in TRUE_VALUES)
    results.expect_eq('SystemCallArchitectures=native',
                      service_values(lines, 'SystemCallArchitectures')[-1:],
                      ['native'])
    lockp = service_values(lines, 'LockPersonality')
    results.check('LockPersonality enabled',
                  bool(lockp) and lockp[-1].lower() in TRUE_VALUES)
    ## Effective value: an empty 'NoExecPaths=' resets it, so the LAST
    ## assignment must be non-empty, not merely present.
    noexec = service_values(lines, 'NoExecPaths')
    results.check('NoExecPaths set', bool(noexec) and noexec[-1] != '')

    ## memfd_create must be effectively denied, and via a soft errno not a kill.
    results.expect_eq(
        'memfd_create denied via a soft errno (EPERM), not a SIGSYS kill',
        memfd_denial(text), 'soft')

    ## NoNewPrivileges must stay false here: it is HONORED (root+CAP_SYS_ADMIN,
    ## NoNewPrivs=0) and intentional, so an escalated action can use a SUID helper
    ## (sudo-like role). Declaring yes would silently break SUID/file-cap actions.
    nnp = service_values(lines, 'NoNewPrivileges')
    results.check(
        'NoNewPrivileges not declared yes (would break SUID actions on this '
        'root+CAP_SYS_ADMIN service)',
        all(value.lower() not in TRUE_VALUES for value in nnp))

    return results.report('privleapd.service W^X static lint')


if __name__ == '__main__':
    raise SystemExit(main())
