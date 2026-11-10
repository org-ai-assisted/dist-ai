#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of qubes-whonix-redirect-9050.service's W^X hardening -- core lane
(no root, no systemd), via the shared dist_ai_wx_lint engine.

A systemd-socket-proxyd leaf unit: `~memfd_create` -> SIGSYS (default), correct
for a write-nothing C forwarder. Resolved via QUBES_WHONIX_REPO, else installed.
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
    lint = Lint('qubes-whonix-redirect-9050.service W^X static lint')
    lint.check_unit(
        'QUBES_WHONIX_REPO',
        'usr/lib/systemd/system/qubes-whonix-redirect-9050.service',
        lambda text: denylist_findings(
            text, noexecpaths='/run /tmp /var/tmp /dev/shm /dev'))
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
