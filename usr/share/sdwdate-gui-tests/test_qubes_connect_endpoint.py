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
is gone. This test runs one iteration of the real script with stubbed
dependencies and asserts both directions.
"""

# pylint: disable=invalid-name

import os
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


def _locate_script(name: str) -> Path:
    try:
        import sdwdate_gui  # pylint: disable=import-outside-toplevel
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise unittest.SkipTest(
            "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
            'or set PYTHONPATH to its dist-packages directory'
        ) from exc
    start = Path(sdwdate_gui.__file__).resolve()
    for ancestor in start.parents:
        candidate = ancestor / 'libexec' / 'sdwdate-gui' / name
        if candidate.is_file():
            return candidate
    raise unittest.SkipTest(f"could not locate the '{name}' script")


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestQubesConnectEndpoint(unittest.TestCase):
    """sdwdate-gui-qubes-connect maintains the Connect endpoint self-healingly."""

    def setUp(self) -> None:
        self.script = _locate_script('sdwdate-gui-qubes-connect')
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

        self.stub_dir = self.tmp / 'stubs'
        self.bin_dir = self.tmp / 'bin'
        self.stub_dir.mkdir()
        self.bin_dir.mkdir()

        self.endpoint = self.tmp / 'sdwdate-gui.Connect'
        self.sock_path = self.tmp / 'sdwdate-gui-server.socket'

        ## light_sleep stub: exit after the first call so the otherwise-infinite
        ## maintenance loop runs exactly one iteration.
        _write_exec(self.stub_dir / 'light_sleep.bsh', 'light_sleep() { exit 0; }\n')
        ## config-read stub: a server VM with sdwdate-gui enabled.
        _write_exec(
            self.stub_dir / 'sdwdate-gui-config-read',
            '#!/bin/bash\n'
            'case "$1" in\n'
            '  run_server_in_qubes) printf \'%s\\n\' true ;;\n'
            '  disable) printf \'%s\\n\' false ;;\n'
            '  *) printf \'%s\\n\' false ;;\n'
            'esac\n',
        )
        ## qubesdb-read stub: so the unused default-user lines do not error
        ## under errexit (the socket path itself is redirected below).
        _write_exec(self.bin_dir / 'qubesdb-read', '#!/bin/bash\nid -un\n')

        text = self.script.read_text(encoding='utf-8')
        text = text.replace(
            '/usr/libexec/helper-scripts/light_sleep.bsh',
            str(self.stub_dir / 'light_sleep.bsh'),
        )
        text = text.replace(
            '/usr/libexec/sdwdate-gui/sdwdate-gui-config-read',
            str(self.stub_dir / 'sdwdate-gui-config-read'),
        )
        text = text.replace(
            '/run/qubes-rpc/sdwdate-gui.Connect', str(self.endpoint)
        )
        text = text.replace(
            '"/run/user/${default_user_uid}/sdwdate-gui/sdwdate-gui-server.socket"',
            '"${SDWDATE_TEST_SOCK}"',
        )
        self.run_script = self.tmp / 'sdwdate-gui-qubes-connect'
        _write_exec(self.run_script, text)

    def _run_once(self) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env['PATH'] = f"{self.bin_dir}:{env.get('PATH', '')}"
        env['SDWDATE_TEST_SOCK'] = str(self.sock_path)
        return subprocess.run(
            ['/bin/bash', str(self.run_script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_creates_endpoint_when_socket_present(self) -> None:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(srv.close)
        srv.bind(str(self.sock_path))
        self.assertTrue(stat.S_ISSOCK(os.stat(self.sock_path).st_mode))

        result = self._run_once()
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
        ## No server socket; endpoint is a left-over symlink to a dead socket.
        os.symlink(str(self.sock_path), self.endpoint)
        self.assertTrue(self.endpoint.is_symlink())

        result = self._run_once()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(
            self.endpoint.exists() or self.endpoint.is_symlink(),
            'stale endpoint symlink was not removed when the socket is gone',
        )


if __name__ == '__main__':
    unittest.main()
