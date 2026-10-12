#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for sdwdate-gui-qubes-proxy-helper's role decision.

The helper runs on both gateway and workstation. On a workstation (not a
server VM) it drops the /run/sdwdate-gui-qubes-should-proxy flag so systemd
enables the proxy sockets; on a gateway (server VM) it does nothing, because
the Connect endpoint is a static qrexec socket-service symlink to the server
socket.

The script is source-able, so these tests source it and drive both
apply_proxy_role (directly) and main (through the sdwdate_gui_config_read_cmd
seam), with the flag-file path redirected through the sdwdate_gui_proxy_flag
test seam.
"""

# pylint: disable=invalid-name

import subprocess
import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced


class TestProxyHelperRole(unittest.TestCase):
    """apply_proxy_role drops the flag only on a workstation."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy-helper')

    def _apply(
        self, permitted: str, flag: Path
    ) -> subprocess.CompletedProcess:
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        apply_proxy_role "${PERMITTED}"
        """
        return run_sourced(
            self.script,
            body,
            {'PERMITTED': permitted, 'sdwdate_gui_proxy_flag': str(flag)},
        )

    def test_workstation_drops_flag(self) -> None:
        """run_server_in_qubes != true -> the proxy flag file is created."""
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            result = self._apply('false', flag)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                flag.is_file(),
                'workstation role did not drop the should-proxy flag',
            )

    def test_gateway_no_flag(self) -> None:
        """run_server_in_qubes == true -> no flag is dropped (gateway no-op)."""
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            result = self._apply('true', flag)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                flag.exists(),
                'gateway role wrongly dropped the should-proxy flag',
            )


class TestProxyHelperMain(unittest.TestCase):
    """main reads run_server_in_qubes from config, then applies the role."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy-helper')

    def test_main_workstation_drops_flag(self) -> None:
        """main: run_server_in_qubes false -> apply_proxy_role drops the flag."""
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            body = """
            fake_config_read() { printf '%s\\n' 'false'; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_proxy_flag': str(flag),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                flag.is_file(),
                'main did not drop the should-proxy flag on a workstation',
            )

    def test_main_server_role_drops_no_flag(self) -> None:
        """main: run_server_in_qubes true -> gateway no-op, no flag dropped."""
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            body = """
            fake_config_read() { printf '%s\\n' 'true'; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_proxy_flag': str(flag),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                flag.exists(),
                'main wrongly dropped the should-proxy flag on a server VM',
            )

    def test_main_config_read_failure_exits_nonzero(self) -> None:
        """main: a failing config read exits non-zero and drops no flag."""
        with tempfile.TemporaryDirectory() as tmp_str:
            flag = Path(tmp_str) / 'should-proxy'
            body = """
            fake_config_read() { return 1; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_proxy_flag': str(flag),
                },
            )
            self.assertNotEqual(
                result.returncode,
                0,
                'main exited 0 despite a config-read failure',
            )
            self.assertFalse(
                flag.exists(),
                'main dropped the should-proxy flag despite a config-read '
                'failure',
            )

    def test_main_queries_run_server_in_qubes_key(self) -> None:
        """main asks config for exactly the run_server_in_qubes key, once."""
        with tempfile.TemporaryDirectory() as tmp_str:
            arg_log = Path(tmp_str) / 'arg.log'
            ## Pre-create empty and APPEND each queried key, so a main that
            ## queries extra keys (extra lines) or none (empty file) fails the
            ## exact-match assertion cleanly rather than passing or crashing.
            arg_log.write_text('', encoding='utf-8')
            flag = Path(tmp_str) / 'should-proxy'
            body = """
            fake_config_read() { printf '%s\\n' "$1" >> "${ARG_LOG}"; printf 'true\\n'; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'ARG_LOG': str(arg_log),
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_proxy_flag': str(flag),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                arg_log.read_text(encoding='utf-8').strip(),
                'run_server_in_qubes',
                'main did not query exactly the run_server_in_qubes config key',
            )


if __name__ == '__main__':
    unittest.main()
