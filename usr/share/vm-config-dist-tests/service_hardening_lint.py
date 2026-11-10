#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of vm-config-dist's wlr-resize-watcher.service W^X hardening -- core
lane (no root, no systemd), via the shared dist_ai_wx_lint engine.

wlr-resize-watcher is a pure subprocess driver of /usr/bin/wlr-randr (NO Qt/GTK,
NO Wayland shm surface), so it never calls memfd_create and `~memfd_create` ->
SIGSYS (default) is correct and verified not to break it (wlr-randr allocates no
shm). This is the ONLY vm-config-dist unit carrying the W^X block. User-scope
unit under usr/lib/systemd/user. Resolved via VM_CONFIG_DIST_REPO, else installed.
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
    lint = Lint('wlr-resize-watcher.service W^X static lint')
    lint.check_unit(
        'VM_CONFIG_DIST_REPO',
        'usr/lib/systemd/user/wlr-resize-watcher.service',
        lambda text: denylist_findings(
            text, noexecpaths='/tmp /var/tmp /dev/shm'))
    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
