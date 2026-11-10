#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of msgcollector-gui.service's W^X hardening -- core lane (no root, no
systemd), via the shared dist_ai_wx_lint engine.

This is the REGRESSION TEST for the GUI-render rollout bug: msgdispatcher pipes
every message to msgdispatcher_dispatch_x.py, a PyQt5 QDialog that inherits this
unit's seccomp filter and calls memfd_create to map its shm draw buffer. Under
the systemd DEFAULT (SIGSYS) it was killed (signal 31) on EVERY message; the fix
is `SystemCallErrorNumber=EPERM`, which keeps memfd_create denied (W^X bypass
closed) while letting Qt fall back to shm_open and render. So memfd MUST be
'soft' (EPERM) here, not the SIGSYS default. Resolved via MSGCOLLECTOR_REPO.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_wx_lint import Lint, denylist_findings, self_check  # noqa: E402


def main() -> int:
    self_check()
    lint = Lint('msgcollector-gui.service W^X static lint')
    lint.check_unit(
        'MSGCOLLECTOR_REPO',
        'usr/lib/systemd/user/msgcollector-gui.service',
        lambda text: denylist_findings(
            text, noexecpaths='/tmp /var/tmp /dev/shm', memfd='soft'))
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
