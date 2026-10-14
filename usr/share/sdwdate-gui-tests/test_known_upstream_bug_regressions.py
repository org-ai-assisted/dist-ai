#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression guards for CONFIRMED-but-UNFIXED upstream sdwdate-gui bugs.

Each test asserts the CORRECT behavior and is marked expectedFailure, so it
reports as an expected failure (xfail) today and, the moment the upstream bug
is fixed, flips to an unexpected success (unittest reports unexpectedSuccess,
which FAILS the suite) -- a loud signal to convert it into a plain assertion.
Each guard was proven NON-vacuous: under a simulated fix it xpasses.

The subject is ArrayBolt3's trixie code; fixes require ArrayBolt3's approval
(each guard names its org-ai-assisted/sdwdate-gui issue). These guards close
the test-suite seams that let the bugs escape: the client-encode -> server-parse
path (#10, #14), the multi-client Tor-status aggregation (#11), and the client
reconnect buffer reset (#13).

org-ai-assisted/sdwdate-gui#12 (ConnectCheck ignoring run_server_in_qubes) is
NOT guarded here: the fix lives in the ConnectCheck bash script, which hardcodes
its /run and /usr/libexec paths with no overridable base, so it cannot be driven
in this python unit suite without a synthetic copy (forbidden by the dist-ai
no-synthetic-copies rule) or a non-portable mount namespace. Its regression
coverage belongs to the integration / kcov lane that runs the real scripts.

All guards import and drive the REAL subject functions -- no vendored copies.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access
# pylint: disable=invalid-name,import-outside-toplevel

import asyncio
import os
import unittest
import unittest.mock as mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_client as client
    from sdwdate_gui import sdwdate_gui_server as server
    from sdwdate_gui import sdwdate_gui_shared as shared
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard

    subject_guard.skip_if_subject_absent(exc)

_APP = QApplication.instance() or QApplication(["bug-regressions"])


def _frame(body: bytes) -> bytes:
    """Length-prefix a body as the client's generic_rpc_call does."""
    return len(body).to_bytes(2, byteorder="big", signed=False) + body


def _capture_rpc(coro_factory) -> bytes:
    """Run an async client call, capturing the single generic_rpc_call body."""
    sent: list[bytes] = []

    async def run() -> None:
        async def capture(payload: bytes) -> None:
            sent.append(payload)

        with mock.patch.object(client, "generic_rpc_call", capture):
            await coro_factory()

    asyncio.run(run())
    assert len(sent) == 1, f"expected one rpc call, got {len(sent)}"
    return sent[0]


class ControlCharWireSafety(unittest.TestCase):
    """Issue #10: client status-message escaping vs server printable check."""

    @unittest.expectedFailure
    def test_issue10_control_char_message_is_wire_safe(self) -> None:
        """Guards org-ai-assisted/sdwdate-gui#10 (control-char escaping)."""
        # xfail: regresses until org-ai-assisted/sdwdate-gui#10 is fixed (fixes
        # need ArrayBolt3 approval); unexpected success here means the fix
        # landed -- convert to a real assertion.
        body = _capture_rpc(
            lambda: client.set_sdwdate_status("busy", "syncing\ttime")
        )
        ## The client's OWN encoder output must be accepted by the server
        ## parser. Today the raw TAB trips check_bytes_printable -> ValueError.
        shared.parse_ipc_command(_frame(body))


class ClientNameWireSafety(unittest.TestCase):
    """Issue #14: set_client_name sends os.uname()[1] unescaped."""

    @unittest.expectedFailure
    def test_issue14_client_name_with_space_is_single_arg(self) -> None:
        """Guards org-ai-assisted/sdwdate-gui#14 (unescaped client name)."""
        # xfail: regresses until org-ai-assisted/sdwdate-gui#14 is fixed (fixes
        # need ArrayBolt3 approval); unexpected success here means the fix
        # landed -- convert to a real assertion.
        body = _capture_rpc(lambda: client.set_client_name("my box"))
        _rest, function_name, msg_parts = shared.parse_ipc_command(_frame(body))
        self.assertEqual(function_name, "set_client_name")
        ## The server requires EXACTLY one argument for set_client_name; the
        ## name must not split on a space (the fix escapes it, e.g. my\040box,
        ## which parse keeps as a single token). Today it is ['my', 'box'] ->
        ## two args -> kick. Asserting the arg COUNT is what flips on the fix;
        ## the exact token depends on the chosen escape, so do not pin it.
        self.assertEqual(
            len(msg_parts),
            1,
            f"client name split into {len(msg_parts)} args -> server kicks",
        )


class TorStatusAggregation(unittest.TestCase):
    """Issue #11: DISABLED_RUNNING masks another client's STOPPED/DISABLED."""

    @unittest.expectedFailure
    def test_issue11_tor_outage_not_hidden_by_disabled_running(self) -> None:
        """Guards org-ai-assisted/sdwdate-gui#11 (Tor-status aggregation)."""
        # xfail: regresses until org-ai-assisted/sdwdate-gui#11 is fixed (fixes
        # need ArrayBolt3 approval); unexpected success here means the fix
        # landed -- convert to a real assertion.
        tor_status = server.TorStatus
        sdwdate_status = server.SdwdateStatus

        class _Client:  # pylint: disable=too-few-public-methods
            def __init__(self, tor) -> None:
                self.tor_status = tor
                self.sdwdate_status = sdwdate_status.SUCCESS

        set_icons: list = []

        class _Tray:  # pylint: disable=too-few-public-methods
            ## Recognizable stand-ins for the real QIcon lists; the first tuple
            ## element identifies which list the chosen icon came from.
            tor_icon_list = [("tor", idx) for idx in range(4)]
            sdwdate_icon_list = [("sdwdate", idx) for idx in range(3)]

            def __init__(self, clients) -> None:
                self.client_list = clients

            def setIcon(self, icon) -> None:  # pylint: disable=invalid-name
                set_icons.append(icon)

        tray = _Tray(
            [
                _Client(tor_status.STOPPED),
                _Client(tor_status.DISABLED_RUNNING),
            ]
        )
        ## Drive the REAL method verbatim.
        server.SdwdateTrayIcon.set_tray_icon(tray)
        self.assertTrue(set_icons, "set_tray_icon chose no icon")
        ## A STOPPED Tor on one client must show the Tor error icon, not be
        ## hidden because another client is DISABLED_RUNNING (value 3).
        self.assertEqual(
            set_icons[-1][0],
            "tor",
            "STOPPED Tor outage hidden by a DISABLED_RUNNING client",
        )


class ClientReconnectBufferReset(unittest.TestCase):
    """Issue #13: GlobalData.sock_buf is never reset across reconnect."""

    def setUp(self) -> None:
        self._saved_buf = client.GlobalData.sock_buf
        self._saved_path = client.GlobalData.server_socket_path
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        client.GlobalData.sock_buf = self._saved_buf
        client.GlobalData.server_socket_path = self._saved_path

    @unittest.expectedFailure
    def test_issue13_open_connection_resets_sock_buf(self) -> None:
        """Guards org-ai-assisted/sdwdate-gui#13 (sock_buf not reset)."""
        # xfail: regresses until org-ai-assisted/sdwdate-gui#13 is fixed (fixes
        # need ArrayBolt3 approval); unexpected success here means the fix
        # landed -- convert to a real assertion.
        ## Residual partial frame left by a dropped session.
        client.GlobalData.sock_buf = _frame(b"set") + b"EXTRA"
        client.GlobalData.server_socket_path = mock.Mock(
            exists=mock.Mock(return_value=True)
        )

        async def run() -> None:
            opened = mock.AsyncMock(return_value=(object(), object()))
            with mock.patch("asyncio.open_unix_connection", new=opened):
                await client.open_connection()

        asyncio.run(run())
        ## A fresh (re)connection must start from an empty buffer, so stale
        ## bytes cannot corrupt the next session's framing -> kick -> wedge.
        self.assertEqual(
            client.GlobalData.sock_buf,
            b"",
            "sock_buf not reset on (re)connect; residual wedges next session",
        )


if __name__ == "__main__":
    unittest.main()
