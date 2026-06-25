#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate-gui-server tray-icon menu activation.

The tray menu must open on both a left-click (Trigger) and a right-click
(Context) of the icon, because the automatic context menu set with
setContextMenu() is unreliable on some platforms, notably Qubes OS
(https://forums.whonix.org/t/sdwd-symbol-malefunction/23330). Showing the
menu ourselves on both activation reasons makes both clicks dependable.

Under Wayland the manual popup must be skipped, because a Wayland client
cannot position its own popup at an absolute screen coordinate; there the
menu is left to the compositor via setContextMenu().

These tests exercise the SdwdateTrayIcon.show_menu handler directly under
the Qt offscreen platform plugin. They verify the handler's decision
logic (which activation reasons open the menu, and the Wayland opt-out).
The end-to-end click-delivery path (a real mouse click on an embedded
tray icon arriving as a Trigger/Context activation) is covered separately
by an X11 simulation harness that needs Xvfb, a systray host, and
xdotool, so it is not part of this dependency-light unit suite.
"""

# pylint: disable=wrong-import-position,no-name-in-module

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication, QMenu, QSystemTrayIcon

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        "or set PYTHONPATH to its dist-packages directory"
    ) from exc


_APP: QApplication = QApplication.instance() or QApplication(["sdwdate-gui-tests"])

Reason = QSystemTrayIcon.ActivationReason


class _FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub for SdwdateGuiListener; avoids PID-file / socket side effects."""

    newClient: pyqtSignal = pyqtSignal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        QObject.__init__(self, parent)


class _FakeWaylandApp:  # pylint: disable=too-few-public-methods
    """Stand-in for QApplication that reports the Wayland platform name."""

    @staticmethod
    def platformName() -> str:  # pylint: disable=invalid-name
        """Mirror QApplication.platformName(), reporting Wayland."""
        return "wayland"


class MenuActivationTests(unittest.TestCase):
    """show_menu opens the menu on the right activation reasons."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self._real_qapplication = server.QApplication
        self.tray = server.SdwdateTrayIcon()

        ## Give the menu a real client entry, as a live session would.
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.sdwdate_status = server.SdwdateStatus.SUCCESS
        client.sdwdate_msg = "test"
        client.tor_status = server.TorStatus.ABSENT
        client.client_name = "disp5711"
        client.client_name_set = True
        client.clientNameChanged.emit()
        _APP.processEvents()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.QApplication = self._real_qapplication
        self.tray.menu.hide()
        self.tray.deleteLater()
        _APP.processEvents()

    def _activate(self, reason: "Reason") -> None:
        """Deliver an activation reason to the tray and pump the loop."""
        self.tray.show_menu(reason)
        _APP.processEvents()

    def visible_menu_count(self) -> int:
        """Number of QMenu widgets currently visible in the process."""
        return sum(
            1
            for widget in _APP.allWidgets()
            if isinstance(widget, QMenu) and widget.isVisible()
        )

    def test_left_click_opens_menu(self) -> None:
        """A left-click (Trigger) opens the menu."""
        self._activate(Reason.Trigger)
        self.assertTrue(self.tray.menu.isVisible())
        self.assertEqual(self.visible_menu_count(), 1)

    def test_right_click_opens_menu(self) -> None:
        """A right-click (Context) opens exactly one menu."""
        self._activate(Reason.Context)
        self.assertTrue(self.tray.menu.isVisible())
        ## A right-click must not stack a second, separate menu on top of
        ## the one the automatic context menu would show.
        self.assertEqual(self.visible_menu_count(), 1)

    def test_other_reasons_do_not_open_menu(self) -> None:
        """Double- and middle-click do not open the menu."""
        for reason in (Reason.DoubleClick, Reason.MiddleClick):
            with self.subTest(reason=reason):
                self.tray.menu.hide()
                _APP.processEvents()
                self._activate(reason)
                self.assertFalse(self.tray.menu.isVisible())

    def test_wayland_does_not_self_popup(self) -> None:
        """Under Wayland the handler does not self-popup the menu."""
        ## Under Wayland the handler must return early and leave the menu to
        ## the compositor instead of calling popup() at a bogus coordinate.
        server.QApplication = _FakeWaylandApp
        self._activate(Reason.Trigger)
        self.assertFalse(self.tray.menu.isVisible())
        self._activate(Reason.Context)
        self.assertFalse(self.tray.menu.isVisible())


if __name__ == "__main__":
    unittest.main()
