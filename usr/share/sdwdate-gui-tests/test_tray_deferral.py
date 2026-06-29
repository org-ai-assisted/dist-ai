#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Offscreen unit tests for sdwdate_gui_server.install_tray_when_available.

Guards the deferred-tray fix and the invariants surfaced by review:

- The QSystemTrayIcon is NOT constructed until a system tray host is
  available (so Qt binds the StatusNotifier backend rather than the legacy
  XEmbed fallback -- the bug behind the missing icon in the sysmaint
  session).
- The IPC listener (and thus the server socket) is created IMMEDIATELY,
  independent of tray-host availability, so the bounded Qubes
  proxy-helper wait is not starved when the tray host is late or absent.
- A client that connects before the tray exists is buffered and replayed
  into the tray once it is constructed -- no client is lost.

Runs under the Qt 'offscreen' platform plugin: no X server, no tray, no
real socket. SdwdateGuiListener is stubbed (no PID-file / socket side
effects); QSystemTrayIcon availability and SdwdateTrayIcon construction are
controlled via module-level patches so the deferral logic is exercised
deterministically.
"""

# pylint: disable=wrong-import-position,no-name-in-module,invalid-name

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        "or set PYTHONPATH to its dist-packages directory"
    ) from exc


## A single QApplication must exist for the lifetime of the process.
_APP: QApplication = QApplication.instance() or QApplication(["sdwdate-gui-tests"])


class _FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """SdwdateGuiListener stub: no PID-file / socket setup, tracks instances."""

    newClient: pyqtSignal = pyqtSignal(object)
    instances: list["_FakeListener"] = []

    def __init__(self, parent: QObject | None = None) -> None:
        QObject.__init__(self, parent)
        _FakeListener.instances.append(self)


class _FakeQSTI(QSystemTrayIcon):  # pylint: disable=too-few-public-methods
    """
    QSystemTrayIcon subclass that forces the availability gate. Everything
    else stays real -- crucially __init__, which SdwdateTrayIcon.__init__
    calls as its base while the module global is patched to this class.
    """

    available: bool = False

    @staticmethod
    def isSystemTrayAvailable() -> bool:
        """Report the test-controlled tray-host availability."""
        return _FakeQSTI.available


class TrayDeferralTestCase(unittest.TestCase):
    """Patch the listener, tray class, and availability gate per test."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        self._real_tray = server.SdwdateTrayIcon
        self._real_qsti = server.QSystemTrayIcon
        _FakeListener.instances = []

        ## A spy subclass of the real tray icon: real behaviour
        ## (accept_client etc.) plus instance tracking.
        spy_instances: list[object] = []
        real_tray = self._real_tray

        class _SpyTray(real_tray):  # type: ignore[valid-type,misc]
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)
                spy_instances.append(self)

        self.spy_instances = spy_instances
        server.SdwdateGuiListener = _FakeListener
        server.SdwdateTrayIcon = _SpyTray
        server.QSystemTrayIcon = _FakeQSTI
        _FakeQSTI.available = False
        self._timer = None

    def tearDown(self) -> None:
        if self._timer is not None:
            self._timer.stop()
        for tray in self.spy_instances:
            tray.deleteLater()
        server.SdwdateGuiListener = self._real_listener
        server.SdwdateTrayIcon = self._real_tray
        server.QSystemTrayIcon = self._real_qsti
        _APP.processEvents()

    def test_listener_eager_tray_deferred_without_host(self) -> None:
        """No tray host: listener comes up now, tray is not constructed."""
        _FakeQSTI.available = False
        self._timer = server.install_tray_when_available(_APP)
        _APP.processEvents()

        self.assertEqual(
            len(_FakeListener.instances),
            1,
            "listener must be created immediately, before any tray host",
        )
        self.assertEqual(
            len(self.spy_instances),
            0,
            "tray icon must NOT be constructed while no host is available",
        )
        self.assertTrue(
            self._timer.isActive(),
            "poll timer must keep running until a host appears",
        )

    def test_tray_constructed_when_host_available(self) -> None:
        """Tray host already up: tray is constructed and polling stops."""
        _FakeQSTI.available = True
        self._timer = server.install_tray_when_available(_APP)
        _APP.processEvents()

        self.assertEqual(len(self.spy_instances), 1, "tray must be built")
        self.assertFalse(
            self._timer.isActive(),
            "poll timer must stop once the tray is installed",
        )

    def test_pre_host_client_is_buffered_then_replayed(self) -> None:
        """A client connecting before the tray exists is replayed into it."""
        _FakeQSTI.available = False
        self._timer = server.install_tray_when_available(_APP)
        _APP.processEvents()
        listener = _FakeListener.instances[0]

        client = server.SdwdateGuiClient(QLocalSocket())
        listener.newClient.emit(client)
        _APP.processEvents()

        ## Still no tray, and the client must not have been dropped.
        self.assertEqual(len(self.spy_instances), 0)

        ## A host appears; firing the poll timer runs the install attempt.
        _FakeQSTI.available = True
        self._timer.timeout.emit()
        _APP.processEvents()

        self.assertEqual(len(self.spy_instances), 1)
        tray = self.spy_instances[0]
        self.assertIn(
            client,
            tray.client_list,
            "client buffered before the tray must be replayed into it",
        )


if __name__ == "__main__":
    unittest.main()
