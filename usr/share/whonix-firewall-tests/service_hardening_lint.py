#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of whonix-firewall-restarter.service's W^X hardening -- core lane
(no root, no systemd), via the shared dist_ai_wx_lint engine.

firewall-restarter is a root bash daemon that waits on sdwdate then asks systemd
over D-Bus to restart whonix-firewall.service -- the firewall rules run in THAT
separate unit, not as a child here, so no privilege-gaining child inherits these
restrictions. `~memfd_create` -> SIGSYS (default), correct for this leaf daemon.
It is a NON-escalator (NoNewPrivileges=yes). ProtectSystem=full (not strict: it
may touch /var,/run). Resolved via WHONIX_FIREWALL_REPO, else the installed path.
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
    lint = Lint('whonix-firewall-restarter.service W^X static lint')
    lint.check_unit(
        'WHONIX_FIREWALL_REPO',
        'usr/lib/systemd/system/whonix-firewall-restarter.service',
        lambda text: denylist_findings(
            text, noexecpaths='/run /tmp /var/tmp /dev/shm /dev'))
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
