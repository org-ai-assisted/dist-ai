#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for sdwdate-gui-qubes-connect-setup, the gateway boot one-shot that
creates the sdwdate-gui.Connect qrexec socket-service symlink.

It must point the symlink at the server socket of the account the active BOOT
MODE runs the GUI as -- 'user' (uid 1000) normally, 'sysmaint' (uid 1001) in a
sysmaint session -- and only on a server VM. The script is source-able; these
tests source it and drive its functions, stubbing `id`, the config read, and
the boot session (so no real accounts and no real sysmaint boot are needed).
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced

## Stubs shared by the tests: resolve the two fixed accounts without needing
## them to exist on the test host, and a config-read returning $RUN_SERVER.
_STUBS = """
id() {
  case "$3" in
    user)     printf '1000\\n' ;;
    sysmaint) printf '1001\\n' ;;
    *)        command id "$@" ;;
  esac
}
fake_config_read() { printf '%s\\n' "${RUN_SERVER}"; }
"""


class TestConnectSetup(unittest.TestCase):
    """The Connect symlink resolves the boot-mode account, gateway-only."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-connect-setup')

    def _run_main(self, run_server: str, boot_session: str, endpoint: Path):
        body = _STUBS + """
        source "${SDWDATE_GUI_SCRIPT}"
        main
        """
        return run_sourced(
            self.script,
            body,
            {
                'RUN_SERVER': run_server,
                'sdwdate_gui_config_read_cmd': 'fake_config_read',
                'sdwdate_gui_boot_session': boot_session,
                'sdwdate_gui_connect_endpoint': str(endpoint),
            },
        )

    def test_user_session_resolves_uid_1000(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            result = self._run_main('true', 'user_session', endpoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(endpoint.is_symlink(), 'no Connect symlink created')
            self.assertEqual(
                endpoint.readlink().as_posix(),
                '/run/user/1000/sdwdate-gui/sdwdate-gui-server.socket',
            )

    def test_sysmaint_session_resolves_uid_1001(self) -> None:
        """The exact sysmaint regression: the endpoint must track uid 1001."""
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            result = self._run_main('true', 'sysmaint_session', endpoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(endpoint.is_symlink(), 'no Connect symlink created')
            self.assertEqual(
                endpoint.readlink().as_posix(),
                '/run/user/1001/sdwdate-gui/sdwdate-gui-server.socket',
                'sysmaint session did not point the endpoint at uid 1001',
            )

    def test_not_a_server_vm_removes_stale_endpoint(self) -> None:
        """
        run_server_in_qubes != true: clean exit, and a stale endpoint from a
        previous server role is REMOVED (a role change server -> client on a
        persistent-/etc StandaloneVM must not leave a symlink that resolves to
        this VM's own proxy socket).
        """
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            endpoint.symlink_to('/run/user/1000/sdwdate-gui/sdwdate-gui-server.socket')
            result = self._run_main('false', 'user_session', endpoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(
                endpoint.exists() or endpoint.is_symlink(),
                'a non-server VM did not remove the stale Connect endpoint',
            )

    def test_config_read_failure_fails_loud_and_closed(self) -> None:
        """
        A config-read FAILURE must exit non-zero (not be swallowed as 'not a
        server') AND fail CLOSED: a stale endpoint is removed, not left behind.
        The server will not start on a broken config, so a surviving Connect
        symlink would point at a socket no server owns (impersonation surface).
        """
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            ## A stale endpoint from a previous (valid-config) server boot.
            endpoint.symlink_to(
                '/run/user/1000/sdwdate-gui/sdwdate-gui-server.socket'
            )
            body = _STUBS.replace(
                'fake_config_read() { printf \'%s\\n\' "${RUN_SERVER}"; }',
                'fake_config_read() { return 1; }',
            ) + """
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'RUN_SERVER': 'true',
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                    'sdwdate_gui_boot_session': 'user_session',
                    'sdwdate_gui_connect_endpoint': str(endpoint),
                },
            )
            self.assertNotEqual(
                result.returncode, 0,
                'a config-read failure was silently swallowed (should fail loud)',
            )
            self.assertFalse(
                endpoint.exists() or endpoint.is_symlink(),
                'a stale endpoint survived a config-read failure (fail-open)',
            )

    def test_endpoint_is_replaced_idempotently(self) -> None:
        """A stale endpoint (wrong target) is overwritten, not duplicated."""
        with tempfile.TemporaryDirectory() as tmp_str:
            endpoint = Path(tmp_str) / 'sdwdate-gui.Connect'
            endpoint.symlink_to('/run/user/9999/stale.socket')
            result = self._run_main('true', 'user_session', endpoint)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                endpoint.readlink().as_posix(),
                '/run/user/1000/sdwdate-gui/sdwdate-gui-server.socket',
                'a stale endpoint was not relinked',
            )


if __name__ == '__main__':
    unittest.main()
