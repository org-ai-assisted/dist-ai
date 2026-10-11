#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for the sdwdate_gui_server crash-hardening.

The gateway server was observed terminating with no logged cause: an exception
escaping a Qt slot makes PyQt abort (SIGABRT), and with the server's stderr not
captured and core dumps disabled the death left nothing in the journal.

Guards here:
  - kick_client must not let a TypeError from disconnect() (raised when the
    "disconnected" signal has nothing connected, e.g. a second kick) escape and
    abort the process.
  - log_unhandled_exception must LOG an unhandled exception (so a future abort
    is diagnosable) and pass KeyboardInterrupt through to the default hook.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position

import os
import unittest
import unittest.mock as mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        'or set PYTHONPATH to its dist-packages directory'
    ) from exc


_APP: QApplication = QApplication.instance() or QApplication(
    ['sdwdate-gui-tests']
)


class TestKickClientDisconnectGuard(unittest.TestCase):
    """kick_client must tolerate disconnect() raising TypeError."""

    def test_typeerror_on_disconnect_does_not_escape(self) -> None:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(client.deleteLater)
        ## Force disconnect() of the "disconnected" signal to raise, as it does
        ## when nothing is connected (the second-kick path).
        client.client_socket = mock.MagicMock()
        client.client_socket.disconnected.disconnect.side_effect = TypeError
        real_qubes = server.running_in_qubes_os
        server.running_in_qubes_os = lambda: False
        try:
            ## Must not raise. Before the guard this TypeError aborted the
            ## process.
            client.kick_client()
        finally:
            server.running_in_qubes_os = real_qubes
        self.assertTrue(client.kick_in_progress)
        client.client_socket.disconnected.disconnect.assert_called_once()


class TestLogUnhandledException(unittest.TestCase):
    """log_unhandled_exception logs, and defers KeyboardInterrupt."""

    def test_logs_critical(self) -> None:
        with self.assertLogs(level='CRITICAL') as caught:
            server.log_unhandled_exception(
                ValueError, ValueError('boom'), None
            )
        self.assertTrue(
            any('Unhandled exception' in line for line in caught.output)
        )

    def test_keyboardinterrupt_deferred_to_default_hook(self) -> None:
        with mock.patch.object(server.sys, '__excepthook__') as default_hook:
            server.log_unhandled_exception(
                KeyboardInterrupt, KeyboardInterrupt(), None
            )
        default_hook.assert_called_once()


if __name__ == '__main__':
    unittest.main()
