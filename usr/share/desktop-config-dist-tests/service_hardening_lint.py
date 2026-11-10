#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of livecheck.service's W^X hardening -- core lane (no root, no
systemd), via the shared dist_ai_wx_lint engine.

REGRESSION TEST for the GUI-render rollout bug: livecheck is CPython + PyQt6 and
maps a real window/menu surface (LiveTextWindow + context menu), so its own Qt
code calls memfd_create for shm draw buffers. Under the systemd DEFAULT (SIGSYS)
it was killed (signal 31) the instant it drew; the fix is
`SystemCallErrorNumber=EPERM` (memfd_create stays denied, Qt falls back to
shm_open and renders). So memfd MUST be 'soft' (EPERM). livecheck.service is the
only desktop-config-dist unit carrying the W^X block. User-scope unit. Resolved
via DESKTOP_CONFIG_DIST_REPO, else the installed path.
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
    lint = Lint('livecheck.service W^X static lint')
    lint.check_unit(
        'DESKTOP_CONFIG_DIST_REPO',
        'usr/lib/systemd/user/livecheck.service',
        lambda text: denylist_findings(
            text, noexecpaths='/tmp /var/tmp /dev/shm', memfd='soft'))  # nosec B108 -- systemd NoExecPaths directive value, not a temp path
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
