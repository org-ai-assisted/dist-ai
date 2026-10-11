#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression test for sdwdate-gui-qubes-connect, the gateway endpoint maintainer.

Bug it replaces: sdwdate-gui-qubes-proxy-helper created the
/run/qubes-rpc/sdwdate-gui.Connect symlink in a one-shot, 20-second-bounded
wait that raced the server socket and never retried. If the server (a Qt app)
bound its socket after the window, or restarted later, the endpoint stayed
permanently absent and every workstation polled ConnectCheck forever.

sdwdate-gui-qubes-connect is self-healing: on each iteration it (re)creates the
endpoint when the server socket is present and removes a stale endpoint when it
is gone. The script is source-able, so these tests source it and call its
functions directly (no copy, no path rewriting). The endpoint and server-socket
paths are env-overridable test seams; safe-rm is a plain shell-function stub.
"""

# pylint: disable=invalid-name

import os
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from bash_harness_common import locate_script, run_sourced


class TestQubesConnectEndpoint(unittest.TestCase):
    """sdwdate-gui-qubes-connect maintains the Connect endpoint self-healingly."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-connect')
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.endpoint = self.tmp / 'sdwdate-gui.Connect'
        self.sock_path = self.tmp / 'sdwdate-gui-server.socket'
        self.ln_log = self.tmp / 'ln.log'

    def _maintain(self) -> subprocess.CompletedProcess:
        ## safe-rm and ln are stubbed as shell functions: safe-rm maps to rm so
        ## no safe-rm binary is required, ln records its calls so a no-churn
        ## pass can be asserted while still performing the real symlink.
        body = """
        safe-rm() { rm "$@"; }
        ln() { printf '%s\\n' "$*" >> "${LN_LOG}"; command ln "$@"; }
        source "${SDWDATE_GUI_SCRIPT}"
        maintain_connect_endpoint "${sdwdate_gui_server_socket}"
        """
        return run_sourced(
            self.script,
            body,
            {
                'sdwdate_gui_connect_endpoint': str(self.endpoint),
                'sdwdate_gui_server_socket': str(self.sock_path),
                'LN_LOG': str(self.ln_log),
            },
        )

    def _bind_socket(self) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(srv.close)
        srv.bind(str(self.sock_path))
        self.assertTrue(stat.S_ISSOCK(os.stat(self.sock_path).st_mode))

    def test_creates_endpoint_when_socket_present(self) -> None:
        """A live server socket and no endpoint -> the symlink is created."""
        self._bind_socket()
        result = self._maintain()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            self.endpoint.is_symlink(),
            'endpoint symlink was not created while the server socket exists',
        )
        self.assertEqual(
            os.readlink(self.endpoint),
            str(self.sock_path),
            'endpoint does not point at the live server socket',
        )

    def test_removes_stale_endpoint_when_socket_absent(self) -> None:
        """No server socket; a left-over endpoint symlink is removed."""
        os.symlink(str(self.sock_path), self.endpoint)
        self.assertTrue(self.endpoint.is_symlink())
        result = self._maintain()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(
            self.endpoint.exists() or self.endpoint.is_symlink(),
            'stale endpoint symlink was not removed when the socket is gone',
        )

    def test_no_churn_when_already_correct(self) -> None:
        """Socket present and endpoint already correct -> no re-link (no churn)."""
        self._bind_socket()
        os.symlink(str(self.sock_path), self.endpoint)
        result = self._maintain()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.endpoint.is_symlink())
        self.assertEqual(os.readlink(self.endpoint), str(self.sock_path))
        self.assertFalse(
            self.ln_log.exists(),
            'maintain_connect_endpoint re-linked an already-correct endpoint '
            '(needless churn)',
        )

    def test_relinks_when_pointing_elsewhere(self) -> None:
        """Socket present but endpoint points elsewhere -> re-linked to it."""
        self._bind_socket()
        os.symlink(str(self.tmp / 'some-other-target'), self.endpoint)
        result = self._maintain()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.readlink(self.endpoint), str(self.sock_path))
        self.assertTrue(
            self.ln_log.exists(),
            'maintain_connect_endpoint did not re-link a stale-target endpoint',
        )


class TestQubesConnectGating(unittest.TestCase):
    """server_gating / server_socket_path config + path logic."""

    def setUp(self) -> None:
        self.script = locate_script('sdwdate-gui-qubes-connect')

    def _config_read_stub(self, tmp: Path, mapping: dict[str, str]) -> Path:
        """Write a sdwdate-gui-config-read stub echoing per-key values."""
        lines = ['#!/bin/bash', 'case "$1" in']
        for key, val in mapping.items():
            lines.append(f"  {key}) printf '%s\\n' '{val}' ;;")
        lines.append("  *) exit 1 ;;")
        lines.append('esac')
        path = tmp / 'sdwdate-gui-config-read'
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        path.chmod(0o755)
        return path

    def _gating_rc(self, config_read: Path) -> int:
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        server_gating
        """
        result = run_sourced(
            self.script,
            body,
            {'sdwdate_gui_config_read_cmd': str(config_read)},
        )
        return result.returncode

    def test_gating_maintain_for_enabled_server(self) -> None:
        """run_server_in_qubes=true, disable=false -> rc 0 (maintain)."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            cfg = self._config_read_stub(
                tmp, {'run_server_in_qubes': 'true', 'disable': 'false'}
            )
            self.assertEqual(self._gating_rc(cfg), 0)

    def test_gating_skip_when_not_server(self) -> None:
        """run_server_in_qubes=false -> rc 10 (not a server VM)."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            cfg = self._config_read_stub(
                tmp, {'run_server_in_qubes': 'false', 'disable': 'false'}
            )
            self.assertEqual(self._gating_rc(cfg), 10)

    def test_gating_skip_when_disabled(self) -> None:
        """Enabled server but disable=true -> rc 11 (disabled)."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            cfg = self._config_read_stub(
                tmp, {'run_server_in_qubes': 'true', 'disable': 'true'}
            )
            self.assertEqual(self._gating_rc(cfg), 11)

    def test_gating_config_read_failure(self) -> None:
        """A failing config-read -> rc 1 (caller exits 1)."""
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            cfg = tmp / 'sdwdate-gui-config-read'
            cfg.write_text('#!/bin/bash\nexit 3\n', encoding='utf-8')
            cfg.chmod(0o755)
            self.assertEqual(self._gating_rc(cfg), 1)

    def test_server_socket_path_seam_override(self) -> None:
        """The server-socket seam is echoed verbatim when set."""
        body = """
        source "${SDWDATE_GUI_SCRIPT}"
        server_socket_path
        """
        result = run_sourced(
            self.script,
            body,
            {'sdwdate_gui_server_socket': '/tmp/seam-sock'},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '/tmp/seam-sock')

    def test_server_socket_path_derived_from_uid(self) -> None:
        """Without the seam, the path is derived from qubesdb-read + id -u."""
        body = """
        qubesdb-read() { printf '%s\\n' 'user'; }
        id() { printf '%s\\n' '4242'; }
        source "${SDWDATE_GUI_SCRIPT}"
        server_socket_path
        """
        result = run_sourced(self.script, body, {'sdwdate_gui_server_socket': ''})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            '/run/user/4242/sdwdate-gui/sdwdate-gui-server.socket',
        )


if __name__ == '__main__':
    unittest.main()
