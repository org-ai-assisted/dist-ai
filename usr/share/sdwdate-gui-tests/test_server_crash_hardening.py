#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate_gui_server's make-a-silent-death-diagnosable
behavior.

The gateway server was observed terminating with no logged cause. The server
now logs the reason on every intentional exit path, so a shutdown is
distinguishable in the journal from a crash:
  - exit_on_user_request (the tray "Exit" action) logs the intent, then exits 0.
  - signal_handler logs the received signal number, then exits 128 + signal.
"""

# pylint: disable=invalid-name,protected-access,no-name-in-module
# pylint: disable=wrong-import-position

import os
import signal
import unittest
import unittest.mock as mock

## Offscreen so importing the server (which pulls in PyQt5 widgets) never needs
## a display. These tests mock the tray self, so no live QApplication instance
## is constructed.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


class TestExitOnUserRequest(unittest.TestCase):
    """The tray Exit logs its intent and exits with code 0."""

    def test_logs_and_exits_zero(self) -> None:
        ## Invoked as a slot: triggered passes a bool. Call unbound with a dummy
        ## self so no full tray construction is needed.
        with self.assertLogs(level='INFO') as caught:
            with self.assertRaises(SystemExit) as raised:
                server.SdwdateTrayIcon.exit_on_user_request(mock.Mock(), True)
        self.assertEqual(raised.exception.code, 0)
        self.assertTrue(
            any('exiting' in line.lower() for line in caught.output)
        )


class TestSignalHandler(unittest.TestCase):
    """signal_handler logs the signal and exits 128 + signal."""

    def test_logs_and_exits_with_offset_code(self) -> None:
        with self.assertLogs(level='INFO') as caught:
            with self.assertRaises(SystemExit) as raised:
                server.signal_handler(signal.SIGTERM, None)
        self.assertEqual(raised.exception.code, 128 + int(signal.SIGTERM))
        self.assertTrue(
            any('Received signal' in line for line in caught.output)
        )


if __name__ == '__main__':
    unittest.main()
