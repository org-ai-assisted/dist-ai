#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for the sdwdate_gui_server crash-hardening.

The gateway server was observed terminating with no logged cause. The reachable
silent-exit path was the tray "Exit" action wired directly to sys.exit: a
QAction.triggered passes a bool, so sys.exit(checked) raised SystemExit inside
the Qt event loop and PyQt turned it into an exit with no log line, easy to
trigger by accident via the "&Exit" mnemonic. A real unhandled exception in a
slot likewise aborted silently (stderr uncaptured, cores disabled).

Guards here:
  - exit_on_user_request logs the intent and quits the event loop cleanly, so an
    intentional or accidental Exit is distinguishable in the journal from a crash.
  - log_unhandled_exception LOGS an unhandled exception (making any abort
    diagnosable) and defers KeyboardInterrupt to the default hook.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position

import os
import unittest
import unittest.mock as mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

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


class TestExitOnUserRequest(unittest.TestCase):
    """The tray Exit must log and quit cleanly, not silently raise SystemExit."""

    def test_logs_and_quits_cleanly(self) -> None:
        with mock.patch.object(server.QApplication, 'quit') as quit_app:
            with self.assertLogs(level='INFO') as caught:
                ## Invoked as a slot: triggered passes a bool. Call unbound with
                ## a dummy self so no full tray construction is needed.
                server.SdwdateTrayIcon.exit_on_user_request(mock.Mock(), True)
        quit_app.assert_called_once()
        self.assertTrue(
            any('Exit requested' in line for line in caught.output)
        )


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
