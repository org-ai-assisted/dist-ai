## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared platform guard for the secure-terminal Qt test suites.

The Qt suites run ONLY on a real headless Wayland compositor (labwc, started by the
runners via usr/share/dist-ai-tests-common/wl-headless-run), never on the offscreen
QPA platform. require_wayland() fails LOUD when a suite is started without a
compositor, so a misconfigured or bare run can never silently fall back to offscreen
and read green on the wrong platform (a false pass on an untested platform).

Import and call at the very top of each Qt suite, BEFORE importing PyQt6 / creating a
QApplication:

    from st_qt_platform import require_wayland
    require_wayland('secure-terminal-tests(<suite>)')
"""

import os
import sys


def require_wayland(suite):
    """Ensure a real Wayland compositor is present; otherwise exit 1 (fail loud).

    The runners (secure-terminal-tests*) re-exec under wl-headless-run, which exports
    QT_QPA_PLATFORM=wayland + WAYLAND_DISPLAY. A bare desktop Wayland session sets
    WAYLAND_DISPLAY but may leave QT_QPA_PLATFORM unset -- pin it to 'wayland' so Qt
    cannot auto-pick another plugin. A run with no compositor, or one that forces a
    non-wayland platform (e.g. offscreen), is rejected."""
    display = os.environ.get('WAYLAND_DISPLAY')
    platform = os.environ.get('QT_QPA_PLATFORM')
    if display and platform in (None, '', 'wayland'):
        os.environ['QT_QPA_PLATFORM'] = 'wayland'
        return
    sys.stderr.write(
        '%s: FATAL: the Qt suites run only on a real headless Wayland compositor '
        '(need WAYLAND_DISPLAY set and QT_QPA_PLATFORM=wayland); offscreen is not '
        'supported. Run via secure-terminal-tests, or directly under: '
        'wl-headless-run --no-autoconfirm -- ./%s\n'
        % (suite, os.path.basename(sys.argv[0]) or 'test_<suite>.py'))
    sys.exit(1)
