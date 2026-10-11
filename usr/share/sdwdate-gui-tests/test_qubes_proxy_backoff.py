#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression test for the sdwdate-gui-qubes-proxy ConnectCheck poll.

Bug: the workstation proxy polled sdwdate-gui.ConnectCheck at a FIXED 1 Hz
with no backoff and no upper bound. Every poll is a qrexec call that dom0's
qrexec-policy-daemon logs, so whenever the gateway endpoint is slow or absent
the dom0 journal is flooded at one line per client VM per second, forever.

Fix: capped exponential backoff (1, 2, 4, ... up to a cap), implemented with
the helper-scripts light_sleep function.

The proxy script is source-able, so these tests source the real script and
call its functions directly -- no copy, no path rewriting. Stubs for
light_sleep and qrexec-client-vm are plain shell functions defined in the
harness before the source, so the real backoff logic runs without real sleeps
or real qrexec calls.
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced


class TestQubesProxyBackoff(unittest.TestCase):
    """sdwdate-gui-qubes-proxy must back off, not poll at a fixed 1 Hz."""

    ## Number of 'n' (not-ready) ConnectCheck replies before a 'y'. Chosen so
    ## the backoff reaches and holds at the cap for a few iterations.
    connectcheck_n = 8
    expected_delays = ['1', '2', '4', '8', '16', '32', '64', '64', '64']

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    def test_backoff_is_capped_exponential(self) -> None:
        """poll_connect_check sleeps 1,2,4,...,cap then saturates at the cap."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            light_sleep_log = tmp / 'light_sleep.log'
            qrexec_count = tmp / 'qrexec.count'
            body = """
            light_sleep() { printf '%s\\n' "$1" >> "${LIGHT_SLEEP_LOG}"; }
            qrexec-client-vm() {
              if [ "$2" = 'sdwdate-gui.ConnectCheck' ]; then
                count="$(cat "${QREXEC_COUNT_FILE}" 2>/dev/null || printf '%s' 0)"
                count="$((count + 1))"
                printf '%s\\n' "${count}" > "${QREXEC_COUNT_FILE}"
                if [ "${count}" -le "${CONNECTCHECK_N}" ]; then
                  printf '%s\\n' n
                else
                  printf '%s\\n' y
                fi
              fi
            }
            source "${SDWDATE_GUI_SCRIPT}"
            poll_connect_check 'sys-test-gw'
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'LIGHT_SLEEP_LOG': str(light_sleep_log),
                    'QREXEC_COUNT_FILE': str(qrexec_count),
                    'CONNECTCHECK_N': str(self.connectcheck_n),
                },
            )
            self.assertEqual(
                result.returncode,
                0,
                f'poll_connect_check exited non-zero: {result.returncode}\n'
                f'stdout={result.stdout!r}\nstderr={result.stderr!r}',
            )
            self.assertEqual(
                result.stdout.strip(),
                'y',
                'poll_connect_check did not return the final ready reply',
            )
            self.assertTrue(
                light_sleep_log.is_file(),
                'proxy never called light_sleep -- it is still using a fixed '
                'sleep poll (the dom0 log-spam regression)',
            )
            delays = light_sleep_log.read_text(encoding='utf-8').split()
            self.assertEqual(
                delays,
                self.expected_delays,
                f'proxy backoff is not capped-exponential; got delays {delays}',
            )

    def test_compute_next_backoff_doubles_then_saturates(self) -> None:
        """The pure backoff function doubles up to the cap, then holds."""
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        cur=1
        out=''
        for _ in $(seq 1 9); do
          out="${out}${cur} "
          cur="$(compute_next_backoff "${cur}" 64)"
        done
        printf '%s\\n' "${out}"
        """
        result = run_sourced(self.script, body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.split(),
            ['1', '2', '4', '8', '16', '32', '64', '64', '64'],
        )

    def test_finalize_drops_flag_when_not_ready(self) -> None:
        """A non-'y' outcome drops the gateway-disabled flag and exits 0."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            run_dir = tmp / 'run-sdwdate-gui'
            body = """
            qrexec-client-vm() { printf '%s\\n' 'should not be called'; }
            source "${SDWDATE_GUI_SCRIPT}"
            finalize_connect 'sys-test-gw' 'q'
            """
            result = run_sourced(
                self.script,
                body,
                {'sdwdate_gui_run_dir': str(run_dir)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                (run_dir / 'qubes-gateway-server-disabled').is_file(),
                'finalize_connect did not drop the gateway-disabled flag',
            )

    def test_finalize_calls_connect_when_ready(self) -> None:
        """A 'y' outcome hands the socket to sdwdate-gui.Connect."""
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


if __name__ == '__main__':
    unittest.main()
