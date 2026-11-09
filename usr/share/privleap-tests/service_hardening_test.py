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
fooled by any of those would report a confident wrong pass. (The parser mirrors
the one in systemcheck-tests/test_wx_seccomp_filter.py; a cross-suite shared
module is not on either suite's import path, so the two are kept in step by hand,
like sdwdate-tests/test_seccomp_filter.py.)

Resolves the unit via PRIVLEAP_REPO (dist-ai/CLAUDE.md), else the installed path.
"""

import os
import sys

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import Results  # noqa: E402

TRUE_VALUES = {'true', 'yes', '1', 'on'}
## systemd accepts an errno name or a number 1..4095; anything else (empty,
## 'kill', 0, out of range, junk) is NOT a soft-fail errno.
_ERRNO_MIN, _ERRNO_MAX = 1, 4095


def service_lines(text: str) -> list:
    """Logical directive lines inside the [Service] section, '\\'-continuations
    joined. systemd ignores these directives outside [Service], so the lint must
    too."""
    out: list = []
    buf: str = ''
    in_service: bool = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            in_service = stripped.lower() == '[service]'
            continue
        if not in_service or stripped.startswith('#'):
            continue
        if stripped.endswith('\\'):
            buf += stripped[:-1] + ' '
        else:
            out.append((buf + stripped).strip())
            buf = ''
    if buf:
        out.append(buf.strip())
    return out


def service_values(lines: list, key: str) -> list:
    prefix = key + '='
    return [line[len(prefix):].strip() for line in lines
            if line.startswith(prefix)]


def errno_is_soft(value: str) -> bool:
    val = value.strip()
    if not val or val.lower() == 'kill':
        return False
    if val.isdigit():
        return _ERRNO_MIN <= int(val) <= _ERRNO_MAX
    ## an errno name like EPERM / EACCES
    return val.replace('_', '').isalpha()


def memfd_denial(text: str) -> str:
    """'none' | 'soft' | 'kill' for memfd_create under [Service], honoring
    SystemCallFilter= empty-reset, a per-syscall ':' action (which overrides the
    global SystemCallErrorNumber), and the global SystemCallErrorNumber. Only
    '~' denylists are modelled -- the form our units use; an allowlist would need
    separate handling and is out of scope here."""
    lines = service_lines(text)
    effective: list = []
    for value in service_values(lines, 'SystemCallFilter'):
        if value == '':
            effective = []
        else:
            effective.append(value)
    denied = False
    per_syscall = None
    for value in effective:
        if not value.startswith('~'):
            continue
        for token in value[1:].split():
            if token.split(':', 1)[0] == 'memfd_create':
                denied = True
                per_syscall = token.split(':', 1)[1] if ':' in token else None
    if not denied:
        return 'none'
    if per_syscall is not None:
        ## per-syscall action takes precedence over the global errno
        return 'soft' if errno_is_soft(per_syscall) else 'kill'
    errnos = service_values(lines, 'SystemCallErrorNumber')
    if errnos and errno_is_soft(errnos[-1]):
        return 'soft'
    return 'kill'


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

    ## Hardening intact (section-aware: directives outside [Service] are inert).
    results.expect_eq('MemoryDenyWriteExecute enabled',
                      service_values(lines, 'MemoryDenyWriteExecute')[-1:],
                      ['true'])
    results.expect_eq('SystemCallArchitectures=native',
                      service_values(lines, 'SystemCallArchitectures')[-1:],
                      ['native'])
    results.expect_eq('LockPersonality enabled',
                      service_values(lines, 'LockPersonality')[-1:], ['true'])
    results.check('NoExecPaths set',
                  bool(service_values(lines, 'NoExecPaths')))

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
