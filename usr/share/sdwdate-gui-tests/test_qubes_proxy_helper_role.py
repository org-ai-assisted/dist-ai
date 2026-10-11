#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for sdwdate-gui-qubes-proxy-helper's role decision.

The helper runs on both gateway and workstation. On a workstation (not a
server VM) it drops the /run/sdwdate-gui-qubes-should-proxy flag so systemd
enables the proxy sockets; on a gateway (server VM) it does nothing, because
the Connect endpoint is maintained continuously by
sdwdate-gui-qubes-connect.service.

The script is source-able, so these tests source it and call apply_proxy_role
directly, with the flag-file path redirected through the sdwdate_gui_proxy_flag
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


if __name__ == '__main__':
    unittest.main()
