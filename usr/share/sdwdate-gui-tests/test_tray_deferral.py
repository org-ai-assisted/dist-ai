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
- The MAX_CLIENTS cap is enforced while buffering, so a late/absent tray
  host cannot let early connections accumulate without bound.
- A client that finishes its handshake while buffered (name set before the
  tray wires clientNameChanged) is still subject to the duplicate-name
  policy when it is replayed.

Runs under the Qt 'offscreen' platform plugin: no X server, no tray, no
real socket. SdwdateGuiListener is stubbed (no PID-file / socket side
effects); QSystemTrayIcon availability and SdwdateTrayIcon construction are
controlled via module-level patches so the deferral logic is exercised
deterministically.
"""

# pylint: disable=wrong-import-position,no-name-in-module,invalid-name

import functools
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
        self._real_in_qubes = server.running_in_qubes_os
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
        server.running_in_qubes_os = self._real_in_qubes
        _APP.processEvents()

    def set_qubes(self, value: bool) -> None:
        """Pin running_in_qubes_os so the duplicate-name policy is
        deterministic regardless of the host the suite runs on."""
        server.running_in_qubes_os = lambda: value

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

    def test_buffering_enforces_max_clients(self) -> None:
        """
        With no tray host the replay never runs, so the MAX_CLIENTS cap must
        be applied while buffering -- otherwise early connections accumulate
        without bound. Clients beyond the cap are kicked at buffer time.
        """
        self.set_qubes(False)
        _FakeQSTI.available = False
        self._timer = server.install_tray_when_available(_APP)
        _APP.processEvents()
        listener = _FakeListener.instances[0]

        overflow = 5
        kicked: list[object] = []
        for _ in range(server.MAX_CLIENTS + overflow):
            client = server.SdwdateGuiClient(QLocalSocket())
            client.clientDisconnected.connect(
                functools.partial(kicked.append, client)
            )
            listener.newClient.emit(client)
        _APP.processEvents()

        ## No host yet, so the cap was enforced at buffer time, not by the
        ## replay path's accept_client (which never ran).
        self.assertEqual(len(self.spy_instances), 0)
        self.assertEqual(
            len(kicked),
            overflow,
            "clients beyond MAX_CLIENTS must be kicked while buffering",
        )

        ## A host appears: exactly MAX_CLIENTS survive into the tray.
        _FakeQSTI.available = True
        self._timer.timeout.emit()
        _APP.processEvents()
        tray = self.spy_instances[0]
        self.assertEqual(len(tray.client_list), server.MAX_CLIENTS)

    def test_duplicate_name_revalidated_on_replay(self) -> None:
        """
        A buffered client can finish its handshake (name set) before the
        tray wires clientNameChanged, so the duplicate-name check would be
        skipped for it. The replay path must re-apply the policy: two
        same-named buffered clients must not both survive.
        """
        self.set_qubes(False)
        _FakeQSTI.available = False
        self._timer = server.install_tray_when_available(_APP)
        _APP.processEvents()
        listener = _FakeListener.instances[0]

        ## Both connect (and are buffered) first, then complete their
        ## handshake while buffered -- the bug path. clientNameChanged is
        ## emitted exactly as the real __set_client_name does, but with the
        ## tray not yet constructed it reaches only the client's own
        ## handshake-timer slot, not handle_client_name_change, so the
        ## duplicate check does not run at buffer time.
        first = server.SdwdateGuiClient(QLocalSocket())
        listener.newClient.emit(first)
        second = server.SdwdateGuiClient(QLocalSocket())
        listener.newClient.emit(second)
        for client in (first, second):
            client.client_name = "workstation"
            client.client_name_set = True
            client.clientNameChanged.emit()
        _APP.processEvents()
        self.assertEqual(len(self.spy_instances), 0)

        ## Host appears -> replay. The non-Qubes policy kicks the newcomer.
        _FakeQSTI.available = True
        self._timer.timeout.emit()
        _APP.processEvents()
        tray = self.spy_instances[0]

        self.assertEqual(
            [client.client_name for client in tray.client_list],
            ["workstation"],
            "a duplicate same-name client must be kicked on replay",
        )
        self.assertIn(first, tray.client_list)
        self.assertNotIn(second, tray.client_list)


if __name__ == "__main__":
    unittest.main()
