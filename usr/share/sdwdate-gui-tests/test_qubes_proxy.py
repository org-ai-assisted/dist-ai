#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for the event-based sdwdate-gui-qubes-proxy.

The workstation proxy makes a SINGLE, blocking sdwdate-gui.ConnectCheck call
(the gateway responder is event-based and returns only when the endpoint is
ready), then acts on the one reply: 'y' hands the systemd socket to
sdwdate-gui.Connect; an explicit 'q' (disabled) drops the give-up flag and
exits 0; any other reply (empty / qrexec transport error) is transient, so it
does NOT set the give-up flag and exits non-zero to retry.

The proxy script is source-able, so these tests source the real script and
call its functions directly -- no copy, no path rewriting. qrexec-client-vm is
a plain shell-function stub defined in the harness before the source, so the
real logic runs without real qrexec calls.
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced


class TestQubesProxy(unittest.TestCase):
    """sdwdate-gui-qubes-proxy makes one blocking call, then acts on it."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    def test_run_connect_check_returns_single_reply(self) -> None:
        """run_connect_check echoes the one ConnectCheck reply verbatim."""
        body = """
        qrexec-client-vm() {
          if [ "$2" = 'sdwdate-gui.ConnectCheck' ]; then
            printf '%s\\n' y
          fi
        }
        source "${SDWDATE_GUI_SCRIPT}"
        run_connect_check 'sys-test-gw'
        """
        result = run_sourced(self.script, body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            'y',
            'run_connect_check did not echo the single ConnectCheck reply',
        )

    def test_finalize_calls_connect_when_ready(self) -> None:
        """A 'y' reply hands the socket to sdwdate-gui.Connect, no flag."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            connect_log = tmp / 'connect.log'
            run_dir = tmp / 'run-sdwdate-gui'
            body = """
            qrexec-client-vm() {
              printf '%s %s\\n' "$2" "$1" >> "${CONNECT_LOG}"
            }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' 'y'
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'CONNECT_LOG': str(connect_log),
                    'sdwdate_gui_run_dir': str(run_dir),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                (run_dir / 'qubes-gateway-server-disabled').is_file(),
                'finalize_connect wrongly dropped the disabled flag on ready',
            )
            self.assertEqual(
                connect_log.read_text(encoding='utf-8').strip(),
                'sdwdate-gui.Connect sys-test-gw',
                'finalize_connect did not invoke sdwdate-gui.Connect',
            )

    def test_finalize_drops_flag_when_disabled(self) -> None:
        """A 'q' reply drops the gateway-disabled flag and never calls Connect."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            connect_log = tmp / 'connect.log'
            run_dir = tmp / 'run-sdwdate-gui'
            body = """
            qrexec-client-vm() {
              printf '%s %s\\n' "$2" "$1" >> "${CONNECT_LOG}"
            }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' 'q'
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'CONNECT_LOG': str(connect_log),
                    'sdwdate_gui_run_dir': str(run_dir),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                (run_dir / 'qubes-gateway-server-disabled').is_file(),
                'finalize_connect did not drop the gateway-disabled flag',
            )
            self.assertFalse(
                connect_log.is_file(),
                'finalize_connect wrongly called Connect on a non-ready reply',
            )

    def test_finalize_transient_empty_no_flag_nonzero(self) -> None:
        """
        An empty reply (transient qrexec error) must NOT set the permanent
        give-up flag and must exit non-zero so the next socket activation
        retries -- reserving the flag for an explicit 'q' (C3). A regression
        (treating empty like 'q') sets the flag and exits 0, failing this test.
        """
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            run_dir = tmp / 'run-sdwdate-gui'
            body = """
            qrexec-client-vm() { printf '%s\\n' 'should not be called'; }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' ''
            """
            result = run_sourced(
                self.script,
                body,
                {'sdwdate_gui_run_dir': str(run_dir)},
            )
            self.assertNotEqual(
                result.returncode,
                0,
                'finalize_connect exited 0 on a transient empty reply '
                '(it must fail so the next activation retries)',
            )
            self.assertFalse(
                (run_dir / 'qubes-gateway-server-disabled').is_file(),
                'finalize_connect wrongly set the permanent give-up flag on a '
                'transient empty reply',
            )

    def test_finalize_transient_garbage_no_flag_nonzero(self) -> None:
        """A non-y/non-q reply (e.g. a qrexec stderr line) is transient too."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            run_dir = tmp / 'run-sdwdate-gui'
            body = """
            qrexec-client-vm() { printf '%s\\n' 'should not be called'; }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' 'qrexec-client-vm: command failed'
            """
            result = run_sourced(
                self.script,
                body,
                {'sdwdate_gui_run_dir': str(run_dir)},
            )
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                (run_dir / 'qubes-gateway-server-disabled').is_file(),
                'finalize_connect set the give-up flag on a transient reply',
            )


if __name__ == '__main__':
    unittest.main()
