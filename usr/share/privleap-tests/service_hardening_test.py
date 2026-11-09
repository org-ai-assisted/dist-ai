#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of privleapd.service's W^X hardening -- runs in the core lane (no
root, no systemd), complementing the runtime inheritance proof in e2e_systemd.py.

Two regressions it locks:

  * NoNewPrivileges must NOT be declared false. systemd FORCES
    PR_SET_NO_NEW_PRIVS=1 whenever MemoryDenyWriteExecute= or SystemCallFilter=
    is set, so NoNewPrivileges=false is a silent no-op -- declaring it only
    misleads a reader into thinking escalated actions may regain privilege. It
    must be yes (or absent), never false/no.

  * SystemCallFilter=~memfd_create must carry SystemCallErrorNumber=EPERM. The
    filter inherits into every escalated action (plain fork+exec via shim.py);
    with the default action a denied memfd_create SIGSYS-KILLS the action
    (exit 159) instead of returning a catchable error. EPERM blocks the W^X
    memfd bypass identically while letting an action fail soft.

Resolves the unit via PRIVLEAP_REPO (dist-ai/CLAUDE.md), else the installed path.
"""

import os
import sys

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import Results  # noqa: E402

## systemd's "kill the caller with SIGSYS" -- the default when
## SystemCallErrorNumber= is unset; a real errno (EPERM) fails soft.
KILL_VALUES = {'', 'kill'}
FALSE_VALUES = {'false', 'no', '0', 'off'}


def service_path() -> str:
    repo: str | None = os.environ.get('PRIVLEAP_REPO')
    base: str = repo if repo else '/'
    return os.path.join(
        base, 'usr', 'lib', 'systemd', 'system', 'privleapd.service')


def directive_values(text: str, key: str) -> list:
    """All values assigned to `key`, in order (systemd: last non-empty wins)."""
    out: list = []
    prefix: str = key + '='
    for raw in text.splitlines():
        line: str = raw.strip()
        if line.startswith('#'):
            continue
        if line.startswith(prefix):
            out.append(line[len(prefix):].strip())
    return out


def main() -> int:
    path: str = service_path()
    if not os.path.isfile(path):
        ## style-ok: allow-skip: privleapd.service absent (installed-only run
        ## without PRIVLEAP_REPO); a --component run always has the checkout.
        print(f"SKIP: {path} not found -- set PRIVLEAP_REPO or install privleap.")
        return 77

    with open(path, encoding='utf-8') as handle:
        text: str = handle.read()
    results: Results = Results()

    ## Hardening intact.
    results.expect_eq('MemoryDenyWriteExecute enabled',
                      directive_values(text, 'MemoryDenyWriteExecute')[-1:],
                      ['true'])
    results.expect_eq('SystemCallArchitectures=native',
                      directive_values(text, 'SystemCallArchitectures')[-1:],
                      ['native'])
    results.expect_eq('LockPersonality enabled',
                      directive_values(text, 'LockPersonality')[-1:], ['true'])
    results.check('NoExecPaths set',
                  bool(directive_values(text, 'NoExecPaths')))

    filters: list = directive_values(text, 'SystemCallFilter')
    results.check('SystemCallFilter=~memfd_create present',
                  any('~memfd_create' in value for value in filters))

    ## memfd denial must be a soft errno, not the SIGSYS kill.
    errnos: list = directive_values(text, 'SystemCallErrorNumber')
    results.check(
        'SystemCallErrorNumber set (memfd denial fails soft, not SIGSYS kill)',
        bool(errnos) and errnos[-1].lower() not in KILL_VALUES)

    ## NoNewPrivileges must never be declared false (a void no-op; see docstring).
    nnp: list = directive_values(text, 'NoNewPrivileges')
    results.check(
        'NoNewPrivileges not declared false (systemd forces it on anyway)',
        all(value.lower() not in FALSE_VALUES for value in nnp))

    return results.report('privleapd.service W^X static lint')


if __name__ == '__main__':
    raise SystemExit(main())
