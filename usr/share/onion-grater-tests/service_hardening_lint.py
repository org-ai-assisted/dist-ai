#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of onion-grater.service's W^X hardening -- core lane (no root, no
systemd), replicating privleap-tests/service_hardening_test.py via the shared
dist_ai_wx_lint engine.

onion-grater is the ODD ONE OUT: its SystemCallFilter is an ALLOWLIST (not a
`~memfd_create` denylist), so memfd_create is denied by being ABSENT from the
allow-set -> SIGSYS, the systemd default. SIGSYS is correct here (a leaf CPython
daemon: stem/psutil/yaml, no ctypes/cffi/JIT); EPERM is reserved for escalators
whose filter inherits into exec'd children. NoExecPaths omits /dev here (unlike
the socket-proxyd units). Resolved via ONION_GRATER_REPO, else the installed path.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_wx_lint import Lint, allowlist_findings, self_check  # noqa: E402

## A conservative core the proxy genuinely needs (all present in the unit's
## allow-list); not the whole set, so adding a syscall needs no test edit, but
## dropping one of these -- which would SIGSYS-kill the daemon -- fails.
REQUIRED_SYSCALLS = {
    'read', 'write', 'open', 'openat', 'close', 'socket', 'connect', 'sendto',
    'recvfrom', 'bind', 'listen', 'accept4', 'execve', 'clone', 'mmap',
    'mprotect', 'rt_sigaction', 'getrandom',
}


def main() -> int:
    self_check()
    lint = Lint('onion-grater.service W^X static lint')
    lint.check_unit(
        'ONION_GRATER_REPO',
        'usr/lib/systemd/system/onion-grater.service',
        lambda text: allowlist_findings(
            text, noexecpaths='/run /tmp /var/tmp /dev/shm',
            required_syscalls=REQUIRED_SYSCALLS))
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
