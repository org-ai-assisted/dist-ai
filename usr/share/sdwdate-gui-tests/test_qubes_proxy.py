#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Unit tests for the workstation sdwdate-gui-qubes-proxy.

The gateway Connect endpoint is a STATIC qrexec socket-service symlink, so the
proxy no longer does a readiness handshake: it resolves the gateway VM from
config and bridges the systemd-activated socket (its own stdin/stdout) straight
to the gateway's sdwdate-gui.Connect service. A down/disabled gateway makes the
qrexec call fail fast; the client's reconnect backoff (tested elsewhere), not
this proxy, is what avoids a dom0 policy-log flood.

The proxy script is source-able, so these tests source the real script and call
its functions directly -- no copy, no path rewriting. qrexec-client-vm and
sdwdate-gui-config-read are plain shell-function / command stubs defined in the
harness, so the real logic runs without real qrexec or a real config read.
"""

# pylint: disable=invalid-name

import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced


class TestConnectToGateway(unittest.TestCase):
    """connect_to_gateway bridges stdio to the gateway Connect service."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    def test_invokes_connect_service_with_gateway(self) -> None:
        """connect_to_gateway runs qrexec-client-vm <gateway> sdwdate-gui.Connect."""
        with tempfile.TemporaryDirectory() as tmp_str:
            connect_log = Path(tmp_str) / 'connect.log'
            body = """
            qrexec-client-vm() {
              printf '%s %s\\n' "$1" "$2" >> "${CONNECT_LOG}"
            }
            source "${SDWDATE_GUI_SCRIPT}"
            connect_to_gateway 'sys-test-gw'
            """
            result = run_sourced(
                self.script, body, {'CONNECT_LOG': str(connect_log)}
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                connect_log.read_text(encoding='utf-8').strip(),
                'sys-test-gw sdwdate-gui.Connect',
                'connect_to_gateway did not invoke sdwdate-gui.Connect for the '
                'gateway',
            )

    def test_bridges_stdin_to_the_service(self) -> None:
        """
        The accepted socket is the proxy's stdin/stdout; connect_to_gateway
        must hand it to qrexec-client-vm so data flows both ways. A stub that
        cats stdin proves the stream reaches the service unbroken.
        """
        body = """
        qrexec-client-vm() { cat; }
        source "${SDWDATE_GUI_SCRIPT}"
        printf '%s' 'wire-payload' | connect_to_gateway 'sys-test-gw'
        """
        result = run_sourced(self.script, body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            'wire-payload',
            'connect_to_gateway did not bridge stdin through to the service',
        )

    def test_honors_qrexec_client_cmd_override(self) -> None:
        """The qrexec binary is overridable via sdwdate_gui_qrexec_client_cmd."""
        with tempfile.TemporaryDirectory() as tmp_str:
            marker = Path(tmp_str) / 'override.log'
            body = """
            my_fake_qrexec() { printf 'override %s %s\\n' "$1" "$2" > "${MARKER}"; }
            source "${SDWDATE_GUI_SCRIPT}"
            connect_to_gateway 'sys-test-gw'
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'MARKER': str(marker),
                    'sdwdate_gui_qrexec_client_cmd': 'my_fake_qrexec',
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                marker.read_text(encoding='utf-8').strip(),
                'override sys-test-gw sdwdate-gui.Connect',
                'connect_to_gateway ignored sdwdate_gui_qrexec_client_cmd',
            )


class TestProxyMain(unittest.TestCase):
    """main resolves the gateway from config, then bridges to it."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-proxy')

    def test_resolves_gateway_then_connects(self) -> None:
        """main reads the 'gateway' config value and connects to that VM."""
        with tempfile.TemporaryDirectory() as tmp_str:
            connect_log = Path(tmp_str) / 'connect.log'
            body = """
            fake_config_read() { printf '%s\\n' 'sys-configured-gw'; }
            qrexec-client-vm() { printf '%s %s\\n' "$1" "$2" >> "${CONNECT_LOG}"; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'CONNECT_LOG': str(connect_log),
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                connect_log.read_text(encoding='utf-8').strip(),
                'sys-configured-gw sdwdate-gui.Connect',
                'main did not connect to the configured gateway',
            )

    def test_config_read_failure_exits_nonzero(self) -> None:
        """A failing config read exits non-zero and never calls qrexec."""
        with tempfile.TemporaryDirectory() as tmp_str:
            connect_log = Path(tmp_str) / 'connect.log'
            body = """
            fake_config_read() { return 1; }
            qrexec-client-vm() { printf 'called\\n' >> "${CONNECT_LOG}"; }
            source "${SDWDATE_GUI_SCRIPT}"
            main
            """
            result = run_sourced(
                self.script,
                body,
                {
                    'CONNECT_LOG': str(connect_log),
                    'sdwdate_gui_config_read_cmd': 'fake_config_read',
                },
            )
            self.assertNotEqual(
                result.returncode,
                0,
                'main exited 0 despite a config-read failure',
            )
            self.assertFalse(
                connect_log.is_file(),
                'main called qrexec-client-vm despite a config-read failure',
            )


if __name__ == '__main__':
    unittest.main()
