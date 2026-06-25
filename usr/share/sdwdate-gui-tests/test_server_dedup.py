#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate-gui-server client de-duplication.

Background
----------
On Qubes OS a single VM (for example a DisposableVM "dispNNNN") could be
listed twice in the sdwdate-gui tray menu when it reconnected before the
gateway server had reaped its previous connection. See:
https://forums.whonix.org/t/sdwd-symbol-malefunction/23330

The server enforces a "no two clients with the same name" invariant. The
invariant used to be enforced only on the non-Qubes code path, where the
name is delivered via the set_client_name RPC (which emits
clientNameChanged, driving handle_client_name_change). On Qubes the name
instead arrives from the authenticated qrexec header in
__parse_qubes_data, which set the name but never emitted
clientNameChanged, so the duplicate check was bypassed entirely and
regen_menu rendered one submenu per connection.

These tests drive the real SdwdateTrayIcon / SdwdateGuiClient classes with
unconnected QLocalSocket objects (so no real qrexec or socket I/O is
needed) and assert on the resulting client list and the rendered menu.

The QApplication runs under the "offscreen" Qt platform plugin, so no X
server or system tray is required. The server's SdwdateGuiListener is
stubbed out to avoid its PID-file / listening-socket side effects.
"""

# pylint: disable=wrong-import-position,protected-access,no-name-in-module

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication, QMenu

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
    """
    Drop-in replacement for SdwdateGuiListener that performs none of the
    PID-file or listening-socket setup. Tests inject clients by calling
    SdwdateTrayIcon.accept_client directly, so the newClient signal is
    never emitted, but it must still exist for the connect() in
    SdwdateTrayIcon.__init__.
    """

    newClient: pyqtSignal = pyqtSignal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        QObject.__init__(self, parent)


class DedupTestCase(unittest.TestCase):
    """
    Shared setup: a tray icon with the real listener stubbed out, plus a
    patch hook for running_in_qubes_os.
    """

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self._real_in_qubes = server.running_in_qubes_os
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_in_qubes
        self.tray.deleteLater()
        _APP.processEvents()

    def set_qubes(self, value: bool) -> None:
        """
        Force running_in_qubes_os to a fixed value for the duration of a
        test. Patched on the module object so every reference inside the
        server module sees it.
        """

        server.running_in_qubes_os = lambda: value

    def add_client(
        self,
        name: str,
        sdwdate_status: "server.SdwdateStatus | None" = None,
    ) -> server.SdwdateGuiClient:
        """
        Create a client backed by an unconnected QLocalSocket, register it
        with the tray exactly as accept_client would for a live connection,
        then simulate the moment its name becomes known.

        Both real name-assignment paths (the qrexec header parse and the
        set_client_name RPC) finish by emitting clientNameChanged, so
        emitting it here faithfully reproduces either path and triggers the
        real handle_client_name_change de-duplication logic.
        """

        if sdwdate_status is None:
            sdwdate_status = server.SdwdateStatus.SUCCESS

        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)

        ## Make the client "ready" so regen_menu will actually show it.
        client.sdwdate_status = sdwdate_status
        client.sdwdate_msg = "test"
        client.tor_status = server.TorStatus.ABSENT

        client.client_name = name
        client.client_name_set = True
        client.clientNameChanged.emit()
        _APP.processEvents()
        return client

    def menu_entry_names(self) -> list[str]:
        """
        Return the user-visible per-client labels in the tray menu.

        With more than one client each client is rendered as its own
        submenu titled with the client name. With exactly one client the
        actions are added directly to the top-level menu, so the single
        client is represented by its status submenu's absence; in that case
        the client name is not a menu title and this returns an empty list
        for client labels (callers assert on client_list for that case).
        """

        names: list[str] = []
        for action in self.tray.menu.actions():
            submenu: QMenu | None = action.menu()
            if submenu is not None:
                names.append(action.text())
        return names

    def client_names(self) -> list[str]:
        """Names of the clients the tray currently tracks."""
        return [client.client_name for client in self.tray.client_list]


class QubesDedupTests(DedupTestCase):
    """De-duplication behavior on Qubes OS (authenticated qrexec names)."""

    def test_reconnecting_vm_listed_once(self) -> None:
        """
        Reproduces the forum screenshot: sys-whonix, then disp5711, then a
        second disp5711 (the reconnect). The stale first disp5711 must be
        dropped, leaving exactly one disp5711 entry.
        """

        self.set_qubes(True)

        self.add_client("sys-whonix")
        old_disp = self.add_client("disp5711")
        new_disp = self.add_client("disp5711")

        ## The new connection wins, the stale one is gone.
        self.assertNotIn(old_disp, self.tray.client_list)
        self.assertIn(new_disp, self.tray.client_list)

        ## No VM is listed twice.
        self.assertEqual(sorted(self.client_names()), ["disp5711", "sys-whonix"])
        self.assertEqual(sorted(self.menu_entry_names()), ["disp5711", "sys-whonix"])
        self.assertEqual(self.menu_entry_names().count("disp5711"), 1)

    def test_three_reconnects_collapse_to_one(self) -> None:
        """A flapping VM that reconnects repeatedly still appears once."""

        self.set_qubes(True)

        survivors = [self.add_client("disp9001") for _ in range(4)]
        self.assertEqual(self.client_names(), ["disp9001"])
        ## Only the most recent connection survives.
        self.assertEqual(self.tray.client_list, [survivors[-1]])

    def test_distinct_vms_all_listed(self) -> None:
        """Different VM names are never collapsed."""

        self.set_qubes(True)

        self.add_client("sys-whonix")
        self.add_client("anon-whonix")
        self.add_client("disp5711")
        self.assertEqual(
            sorted(self.client_names()),
            ["anon-whonix", "disp5711", "sys-whonix"],
        )


class NonQubesDedupTests(DedupTestCase):
    """De-duplication behavior off Qubes (self-reported, untrusted names)."""

    def test_duplicate_name_kicks_newcomer(self) -> None:
        """
        Off Qubes the name is self-reported, so a duplicate is treated as an
        impersonation attempt: the established client is kept and the
        newcomer is kicked.
        """

        self.set_qubes(False)

        established = self.add_client("workstation")
        newcomer = self.add_client("workstation")

        self.assertIn(established, self.tray.client_list)
        self.assertNotIn(newcomer, self.tray.client_list)
        self.assertEqual(self.client_names(), ["workstation"])


class QubesHeaderEmitsNameChangeTests(unittest.TestCase):
    """
    Unit test for the one-line server fix itself: parsing a qrexec header
    must emit clientNameChanged so the de-duplication logic runs on Qubes.
    """

    def test_parse_qubes_header_emits_signal(self) -> None:
        """Parsing a qrexec header sets the name and emits the signal."""

        client = server.SdwdateGuiClient(QLocalSocket())

        fired: list[str] = []
        client.clientNameChanged.connect(lambda: fired.append(client.client_name))

        ## qrexec header is "<service> <source-vm> ...\0".
        ## __sock_buf and __parse_qubes_data are name-mangled private members.
        client._SdwdateGuiClient__sock_buf = b"sdwdate-gui.Connect disp5711\0"
        result = client._SdwdateGuiClient__parse_qubes_data()

        self.assertTrue(result)
        self.assertEqual(client.client_name, "disp5711")
        self.assertTrue(client.client_name_set)
        self.assertEqual(fired, ["disp5711"])


if __name__ == "__main__":
    unittest.main()
