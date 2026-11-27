#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of privleapd.service -- runs in the core lane (no root, no systemd).

By design privleapd carries NO W^X seccomp/exec hardening (MemoryDenyWriteExecute,
SystemCallArchitectures, LockPersonality, NoExecPaths, a memfd_create
SystemCallFilter): it must execute arbitrary applications with elevated
privileges, including ones that require W+X. See the "No W^X hardening by design"
note in privleapd.service. The runtime proof that such a W+X action actually runs,
and that the sudo-like SUID path is preserved, lives in e2e_systemd.py's W^X phase.

The one invariant this static lint locks:

  * NoNewPrivileges must NOT be declared yes. privleapd is a root service WITH
    CAP_SYS_ADMIN, so NoNewPrivileges=false is HONORED (NoNewPrivs=0) and
    intentional: an escalated action may still exec a SUID helper, matching the
    sudo-like role. Flipping it to yes would silently break SUID/file-cap actions.
    (A user-scope service, lacking CAP_SYS_ADMIN, would have no_new_privs forced
    on regardless.)

Resolves the unit via PRIVLEAP_REPO (dist-ai/CLAUDE.md), else the installed path.
"""

import os
import sys

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
## The [Service] directive parser is the single-source dist_ai_seccomp, shared with the W^X
## static lint in systemcheck-tests. Insert its dist-packages dir relative to this file (the
## dm_test_results idiom) so this suite imports the same code -- no hand-synced copy to drift.
_LIB: str = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from pl_testlib import Results  # noqa: E402
from dist_ai_seccomp import service_lines, service_values  # noqa: E402

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

    ## NoNewPrivileges must stay false: it is HONORED (root+CAP_SYS_ADMIN,
    ## NoNewPrivs=0) and intentional, so an escalated action can use a SUID helper
    ## (sudo-like role). Declaring yes would silently break SUID/file-cap actions.
    ## Section-aware: a directive outside [Service] is inert.
    nnp = service_values(lines, 'NoNewPrivileges')
    results.check(
        'NoNewPrivileges not declared yes (would break SUID actions on this '
        'root+CAP_SYS_ADMIN service)',
        all(value.lower() not in TRUE_VALUES for value in nnp))

    return results.report('privleapd.service static lint')


if __name__ == '__main__':
    raise SystemExit(main())
