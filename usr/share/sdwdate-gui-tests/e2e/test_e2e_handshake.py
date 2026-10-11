#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
End-to-end automation of the Qubes sdwdate-gui connect handshake, chaining the
REAL components across server up/down transitions in one process -- the cross
-VM scenarios of E2E-LIVE-TEST-PLAN.md that do NOT need live qubes.

Unit suites cover each component in isolation (the maintainer's create/remove,
the responder's y/q, the proxy's finalize). This suite chains them exactly as
the gateway runs them, so a break in the SEAM between them is caught:

  server socket (AF_UNIX) appears/disappears   -- the real sdwdate-gui-server's
                                                   socket, simulated by binding
  -> sdwdate-gui-qubes-connect maintain_connect_endpoint  (real bash function)
       creates/removes /run/.../sdwdate-gui.Connect
  -> sdwdate_gui_connect_check.wait_for_connect_endpoint   (real responder)
       wakes on the inotify event the maintainer's symlink-create fires -> 'y'
  -> sdwdate-gui-qubes-proxy finalize_connect              (real bash function)
       'y' -> Connect; 'q' -> give-up flag; transient -> no flag, non-zero.

Scenario IDs reference E2E-LIVE-TEST-PLAN.md. The live, multi-qube, dom0
-observed scenarios (real qvm lifecycle, dom0 log-spam) stay operator-driven in
that plan; this suite is its headless, no-qubes core.

Run via: dist-ai-tests-all --e2e --component sdwdate-gui --repo-root ~/derivative-maker
"""

# pylint: disable=invalid-name

import os
import socket
import stat
import threading
import unittest
import unittest.mock as mock
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator, Optional

try:
    from sdwdate_gui import sdwdate_gui_connect_check as cc
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)

from bash_harness_common import locate_script, run_sourced

## The maintainer links the endpoint only when the server socket is a real
## AF_UNIX socket ([ -S ]); safe-rm/ln are stubbed so no safe-rm binary is
## needed and the real symlink is still performed.
_MAINTAIN_BODY = """
safe-rm() { rm "$@"; }
source "${SDWDATE_GUI_SCRIPT}"
maintain_connect_endpoint "${sdwdate_gui_server_socket}"
"""

_FINALIZE_BODY = """
qrexec-client-vm() { printf '%s %s\\n' "$2" "$1" >> "${CONNECT_LOG}"; }
source "${SDWDATE_GUI_SCRIPT}"
finalize_connect 'sys-test-gw' "${REPLY}"
"""


@contextmanager
def patched_config(
    disable: bool = False, run_server: bool = True
) -> Iterator[None]:
    """Patch the responder's config read to a fixed (disable, run_server)."""

    def _fake_parse() -> None:
        cc.ConfigData.conf_dict = dict(cc.ConfigData.defaults_dict)
        cc.ConfigData.conf_dict['disable'] = disable
        cc.ConfigData.conf_dict['run_server_in_qubes'] = run_server

    with mock.patch.object(cc, 'parse_config_files', side_effect=_fake_parse):
        yield


class E2EHandshakeBase(unittest.TestCase):
    """Shared gateway-side fixture: a temp /run, a maintainer, a responder."""

    def setUp(self) -> None:
        self.connect_script = locate_script('sdwdate-gui-qubes-connect')
        self.proxy_script = locate_script('sdwdate-gui-qubes-proxy')
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name)
        self.endpoint = self.run_dir / 'sdwdate-gui.Connect'
        self.server_sock = self.run_dir / 'sdwdate-gui-server.socket'
        self._srv: Optional[socket.socket] = None

    ## --- server lifecycle (the real AF_UNIX socket the maintainer checks) ---

    def server_up(self) -> None:
        if self._srv is not None:
            return
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.server_sock))
        self._srv = srv
        self.addCleanup(self._close_server)
        self.assertTrue(stat.S_ISSOCK(os.stat(self.server_sock).st_mode))

    def server_down(self) -> None:
        self._close_server()
        if self.server_sock.exists():
            self.server_sock.unlink()

    def _close_server(self) -> None:
        if self._srv is not None:
            self._srv.close()
            self._srv = None

    ## --- the real maintainer pass ---

    def maintain(self) -> None:
        result = run_sourced(
            self.connect_script,
            _MAINTAIN_BODY,
            {
                'sdwdate_gui_connect_endpoint': str(self.endpoint),
                'sdwdate_gui_server_socket': str(self.server_sock),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    ## --- the real responder, backgrounded so a block cannot hang the suite ---

    def responder_async(self, disable: bool = False, run_server: bool = True):
        box: dict[str, str] = {}

        def _run() -> None:
            with patched_config(disable=disable, run_server=run_server):
                box['reply'] = cc.wait_for_connect_endpoint(
                    str(self.endpoint), str(self.run_dir)
                )

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        return thread, box

    def responder_sync(
        self, disable: bool = False, run_server: bool = True
    ) -> str:
        with patched_config(disable=disable, run_server=run_server):
            return cc.wait_for_connect_endpoint(
                str(self.endpoint), str(self.run_dir)
            )

    ## --- the real proxy reply handler ---

    def finalize(self, reply: str) -> tuple:
        connect_log = self.run_dir / 'connect.log'
        proxy_run_dir = self.run_dir / 'proxy-run'
        result = run_sourced(
            self.proxy_script,
            _FINALIZE_BODY,
            {
                'REPLY': reply,
                'CONNECT_LOG': str(connect_log),
                'sdwdate_gui_run_dir': str(proxy_run_dir),
            },
        )
        connected = connect_log.is_file() and 'sdwdate-gui.Connect' in (
            connect_log.read_text(encoding='utf-8')
        )
        gaveup = (proxy_run_dir / 'qubes-gateway-server-disabled').is_file()
        return result.returncode, connected, gaveup


class TestE2EHandshake(E2EHandshakeBase):
    """The handshake chained across real server up/down transitions."""

    def test_server_up_full_handshake(self) -> None:
        """S2/S3: server up -> endpoint maintained -> 'y' -> Connect called."""
        self.server_up()
        self.maintain()
        self.assertTrue(
            self.endpoint.is_symlink(), 'maintainer did not create the endpoint'
        )
        self.assertEqual(self.responder_sync(), 'y')
        rc, connected, gaveup = self.finalize('y')
        self.assertEqual(rc, 0)
        self.assertTrue(connected, 'proxy did not invoke sdwdate-gui.Connect')
        self.assertFalse(gaveup, 'proxy wrongly set the give-up flag on y')

    def test_server_appears_wakes_waiting_responder(self) -> None:
        """
        S7: a responder is already blocked (server/endpoint absent) when the
        server comes up; the maintainer's symlink-create must wake it via the
        inotify event -> 'y'. Chains the bash maintainer to the python
        responder through the real filesystem event.
        """
        self.assertFalse(self.endpoint.exists())
        thread, box = self.responder_async()
        ## Let the responder arm its watch and take the (absent) fast path.
        thread.join(timeout=0.3)
        self.assertTrue(thread.is_alive(), 'responder returned before endpoint')
        self.server_up()
        self.maintain()
        self.assertTrue(self.endpoint.is_symlink())
        thread.join(timeout=10)
        self.assertFalse(
            thread.is_alive(),
            'responder did not wake when the maintainer created the endpoint',
        )
        self.assertEqual(box.get('reply'), 'y')

    def test_server_drops_then_returns(self) -> None:
        """
        S4+S5: with a live handshake, the server drops (endpoint removed by the
        maintainer), a fresh responder blocks, then the server returns and the
        maintainer re-creates the endpoint, waking it -> 'y' (reconnect).
        """
        self.server_up()
        self.maintain()
        self.assertEqual(self.responder_sync(), 'y')

        ## Server drops: the maintainer removes the now-stale endpoint.
        self.server_down()
        self.maintain()
        self.assertFalse(
            self.endpoint.is_symlink(),
            'maintainer did not remove the stale endpoint when server dropped',
        )

        ## A reconnecting client blocks until the server returns.
        thread, box = self.responder_async()
        thread.join(timeout=0.3)
        self.assertTrue(thread.is_alive(), 'responder returned with no server')
        self.server_up()
        self.maintain()
        thread.join(timeout=10)
        self.assertFalse(
            thread.is_alive(), 'responder did not wake on server return'
        )
        self.assertEqual(box.get('reply'), 'y')

    def test_non_server_vm_gives_up(self) -> None:
        """
        C1: on a VM that does not run the server, the responder gives up ('q')
        terminally and the proxy drops the give-up flag -- never blocking for an
        endpoint that the maintainer will never create here.
        """
        thread, box = self.responder_async(run_server=False)
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), 'responder blocked on a non-server VM')
        self.assertEqual(box.get('reply'), 'q')
        rc, connected, gaveup = self.finalize('q')
        self.assertEqual(rc, 0)
        self.assertTrue(gaveup, 'proxy did not drop the give-up flag on q')
        self.assertFalse(connected)

    def test_disabled_gives_up(self) -> None:
        """S8-adjacent: sdwdate-gui disabled -> 'q' -> give-up flag, no Connect."""
        self.server_up()
        self.maintain()
        self.assertEqual(self.responder_sync(disable=True), 'q')
        rc, connected, gaveup = self.finalize('q')
        self.assertEqual(rc, 0)
        self.assertTrue(gaveup)
        self.assertFalse(connected)

    def test_transient_failure_retries_no_flag(self) -> None:
        """
        C3: a transient ConnectCheck failure (empty reply) must NOT set the
        permanent give-up flag; the proxy exits non-zero so the next socket
        activation retries.
        """
        rc, connected, gaveup = self.finalize('')
        self.assertNotEqual(rc, 0, 'transient empty reply exited 0')
        self.assertFalse(gaveup, 'transient reply wrongly set the give-up flag')
        self.assertFalse(connected)


if __name__ == '__main__':
    unittest.main()
