#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression guard for the msgcollector GUI dialogs' Qt-platform selection.

Every msgcollector script that opens a window builds a QApplication. Qt5
defaults to the "xcb" platform even inside a Wayland session; when no X server
(or XWayland) is reachable -- e.g. the dialog is launched from a .desktop
shortcut on a Wayland-only Kicksecure/Whonix session -- xcb aborts the process
with no window at all. A caller running under "set -o errexit"
(update-torbrowser via its desktop shortcut) then dies silently, which is the
"click the shortcut, nothing happens" bug this test exists to prevent.

The fix is a select_qt_platform() helper in each GUI script that, when the
caller has not pinned QT_QPA_PLATFORM and WAYLAND_DISPLAY is set, prefers
"wayland;xcb" (Wayland first, xcb fallback) before the QApplication is built.
sandbox-update-torbrowser pins QT_QPA_PLATFORM itself and must stay untouched.

This test enumerates EVERY libexec script that constructs a QApplication and
asserts each one:
  * defines select_qt_platform and invokes it before the QApplication; and
  * returns the correct platform for every session/pin combination.

Enumerating by QApplication use (not a hardcoded list) means a NEW GUI script
added without the guard fails here too. Pure-Python: it needs neither PyQt5 nor
a display, so it runs on any CI container.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import msgcollector_testlib as T  # noqa: E402

try:
    GUI_SCRIPTS = T.qt_gui_scripts()
except SystemExit:
    pytest.skip("msgcollector not available", allow_module_level=True)

if not GUI_SCRIPTS:
    pytest.skip("no msgcollector GUI scripts found", allow_module_level=True)

_IDS = [os.path.basename(path) for path in GUI_SCRIPTS]

## (environment, expected select_qt_platform() return value)
##   None         -> leave Qt's own default in place
##   "wayland;xcb"-> prefer Wayland, fall back to xcb
_CASES = [
    ({}, None),                                                    # nothing set
    ({"DISPLAY": ":0"}, None),                                     # X11 session
    ({"WAYLAND_DISPLAY": ""}, None),                               # empty -> not Wayland
    ({"WAYLAND_DISPLAY": "wayland-0"}, "wayland;xcb"),             # Wayland, unpinned
    ({"XDG_SESSION_TYPE": "wayland"}, "wayland;xcb"),              # Wayland via XDG, WAYLAND_DISPLAY unset
    ({"XDG_SESSION_TYPE": "x11"}, None),                           # X11 session
    ({"WAYLAND_DISPLAY": "wayland-0", "QT_QPA_PLATFORM": ""},
     "wayland;xcb"),                                               # empty pin == unpinned
    ({"WAYLAND_DISPLAY": "wayland-0", "QT_QPA_PLATFORM": "xcb"},
     None),                                                        # sandbox pinned xcb
    ({"WAYLAND_DISPLAY": "wayland-0", "QT_QPA_PLATFORM": "wayland"},
     None),                                                        # sandbox pinned wayland
]


def _load_select_qt_platform(path):
    """Extract and define select_qt_platform from a GUI script without
    importing the script (importing would launch its GUI main)."""
    source = T.extract_python_function(path, "select_qt_platform")
    namespace = {}
    exec(source, namespace)  # noqa: S102  (trusted first-party source)
    return namespace["select_qt_platform"]


@pytest.mark.parametrize("path", GUI_SCRIPTS, ids=_IDS)
def test_guard_defined_and_runs_before_qapplication(path):
    text = T.read(path)
    assert "def select_qt_platform" in text, (
        f"{os.path.basename(path)} builds a QApplication but defines no "
        "select_qt_platform guard -- a Wayland .desktop launch would show no "
        "window")
    call_index = text.find("select_qt_platform(os.environ)")
    app_index = text.find("QApplication(sys.argv)")
    assert call_index != -1, (
        f"{os.path.basename(path)} never calls select_qt_platform(os.environ)")
    assert call_index < app_index, (
        f"{os.path.basename(path)}: the guard must run before the "
        "QApplication is constructed")


@pytest.mark.parametrize("path", GUI_SCRIPTS, ids=_IDS)
def test_select_qt_platform_behavior(path):
    select_qt_platform = _load_select_qt_platform(path)
    for environ, expected in _CASES:
        result = select_qt_platform(dict(environ))
        assert result == expected, (
            f"{os.path.basename(path)}: env={environ} -> {result!r}, "
            f"expected {expected!r}")
