#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Mutation-killing regression tests for sdwdate_gui_server.

Each pins behavior cosmic-ray proved executed-but-unasserted: the protocol enum
VALUES (ordering drives the worst-status tray icon), the display-length caps,
the non-Qubes name-length boundary, the frame loop, per-command argument-count
validation, the server->client RPC send framing (exact bytes, partial writes,
disconnect guard), the aggregate tray-icon worst-status selection, and the
context-menu client filter / Tor-entry / placeholder logic.

These drive the real SdwdateTrayIcon / SdwdateGuiClient under the Qt offscreen
platform plugin; no X server or qrexec is required.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access
# pylint: disable=invalid-name

import contextlib
import logging
import os
import signal
import types
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)


_APP = QApplication.instance() or QApplication(["sdwdate-gui-tests"])


class _Timeout(Exception):
    """Raised by the watchdog if the guarded call does not return."""


@contextlib.contextmanager
def watchdog(seconds: float = 2.0):
    """Raise _Timeout if the wrapped block runs longer than `seconds`."""

    def _raise(_sig, _frame):
        raise _Timeout()

    previous = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


from PyQt5.QtCore import QObject, pyqtSignal  # noqa: E402


class _FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub for SdwdateGuiListener; avoids PID-file / socket side effects."""

    newClient = pyqtSignal(object)


def _named_client() -> "server.SdwdateGuiClient":
    """A server-side client past the qrexec header with a name set."""
    client = server.SdwdateGuiClient(QLocalSocket())
    client.qubes_header_parsed = True
    client.client_name = "disp5711"
    client.client_name_set = True
    return client


class _TrayFixture(unittest.TestCase):
    """Builds a real SdwdateTrayIcon with side-effect-free collaborators."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self._real_in_qubes = server.running_in_qubes_os
        server.running_in_qubes_os = lambda: False
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_in_qubes
        if self.tray.msg_window is not None:
            self.tray.msg_window.close()
        self.tray.deleteLater()
        _APP.processEvents()


class TestProtocolEnumValues(unittest.TestCase):
    """Enum values are a wire/ordering contract, pinned to literals."""

    def test_sdwdate_status_values(self) -> None:
        self.assertEqual(server.SdwdateStatus.SUCCESS.value, 0)
        self.assertEqual(server.SdwdateStatus.BUSY.value, 1)
        self.assertEqual(server.SdwdateStatus.ERROR.value, 2)
        self.assertEqual(server.SdwdateStatus.UNKNOWN.value, 0xFF)
        ## Ordering drives the worst-status tray icon pick.
        self.assertLess(
            server.SdwdateStatus.SUCCESS.value, server.SdwdateStatus.BUSY.value
        )
        self.assertLess(
            server.SdwdateStatus.BUSY.value, server.SdwdateStatus.ERROR.value
        )

    def test_tor_status_values(self) -> None:
        self.assertEqual(server.TorStatus.RUNNING.value, 0)
        self.assertEqual(server.TorStatus.DISABLED_RUNNING.value, 1)
        self.assertEqual(server.TorStatus.STOPPED.value, 2)
        self.assertEqual(server.TorStatus.DISABLED.value, 3)
        self.assertEqual(server.TorStatus.ABSENT.value, 0xFE)
        self.assertEqual(server.TorStatus.UNKNOWN.value, 0xFF)

    def test_message_type_values(self) -> None:
        self.assertEqual(server.MessageType.SDWDATE.value, 0)
        self.assertEqual(server.MessageType.TOR.value, 1)
        self.assertEqual(server.MessageType.DISCONNECTED.value, 2)

    def test_length_caps(self) -> None:
        self.assertEqual(server.MAX_DISPLAY_NAME_LEN, 255)
        self.assertEqual(server.MAX_DISPLAY_MSG_LEN, 2048)
        self.assertEqual(server.MAX_CLIENTS, 64)


class TestNameLengthBoundary(_TrayFixture):
    """__set_client_name non-Qubes length boundary (255 chars)."""

    def test_exactly_255_accepted(self) -> None:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        self.assertTrue(client._SdwdateGuiClient__set_client_name("a" * 255))
        self.assertEqual(client.client_name, "a" * 255)

    def test_256_rejected(self) -> None:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))
        self.assertFalse(client._SdwdateGuiClient__set_client_name("a" * 256))
        self.assertEqual(kicked, [True])


class TestFrameLoopAndArgCount(_TrayFixture):
    """__try_parse_commands frame loop + per-command argument counts."""

    @staticmethod
    def _frame(payload: bytes) -> bytes:
        return len(payload).to_bytes(2, "big") + payload

    def test_zero_length_frame_kicks(self) -> None:
        ## A 0-length frame is now rejected by parse_ipc_buf (`msg_len == 0`
        ## raises), so the client is kicked rather than the frame consumed.
        client = _named_client()
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))
        client._SdwdateGuiClient__sock_buf = (0).to_bytes(2, "big")
        with self.assertLogs(level="WARNING"):
            client._SdwdateGuiClient__try_parse_commands()
        self.assertEqual(kicked, [True])

    def test_sdwdate_status_three_args_kicked(self) -> None:
        ## set_sdwdate_status expects exactly 2 args; a 3rd must kick
        ## (pins `!= 2` vs `< 2`).
        client = _named_client()
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))
        payload = b"set_sdwdate_status success hello extra"
        client._SdwdateGuiClient__sock_buf = self._frame(payload)
        client._SdwdateGuiClient__try_parse_commands()
        self.assertEqual(kicked, [True])

    def test_tor_status_two_args_kicked(self) -> None:
        ## set_tor_status expects exactly 1 arg; a 2nd must kick
        ## (pins `!= 1` vs `< 1`).
        client = _named_client()
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))
        payload = b"set_tor_status running extra"
        client._SdwdateGuiClient__sock_buf = self._frame(payload)
        client._SdwdateGuiClient__try_parse_commands()
        self.assertEqual(kicked, [True])


class TestGenericRpcSend(_TrayFixture):
    """__generic_rpc_call wire framing, partial writes, and guards."""

    def test_exact_frame_bytes_partial_writes(self) -> None:
        """Across one-byte partial writes the exact length-prefixed frame is
        sent and the client is not kicked."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState
        sent = bytearray()

        def rec(data: bytes) -> int:
            raw = bytes(data)
            if not raw:
                return 0
            sent.append(raw[0])
            return 1

        client.client_socket.write = rec  # type: ignore[assignment]
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))

        body = b"set_tor_status running"
        with watchdog(2.0):
            client._SdwdateGuiClient__generic_rpc_call(body)

        expected = len(body).to_bytes(2, "big") + body
        self.assertEqual(bytes(sent), expected)
        self.assertEqual(kicked, [])

    def test_disconnected_socket_sends_nothing(self) -> None:
        """A non-connected socket is not written to (send-loop state guard)."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.UnconnectedState
        sent: list[bytes] = []

        def _record(data: bytes) -> int:
            sent.append(bytes(data))
            return len(data)

        client.client_socket.write = _record  # type: ignore[assignment]
        with watchdog(2.0):
            client._SdwdateGuiClient__generic_rpc_call(b"set_tor_status running")
        self.assertEqual(sent, [])

    def test_exactly_max_not_exited(self) -> None:
        """A message of exactly MAX_MSG_SIZE bytes does not exit (pins `>`)."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState

        def _accept(data: bytes) -> int:
            return len(data)

        client.client_socket.write = _accept  # type: ignore[assignment]
        with watchdog(2.0):
            client._SdwdateGuiClient__generic_rpc_call(b"x" * server.MAX_MSG_SIZE)

    def test_oversized_send_exits_one(self) -> None:
        """An oversized RPC send exits 1 (failure), not 0/2 (pins the code)."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState
        with self.assertRaises(SystemExit) as ctx:
            client._SdwdateGuiClient__generic_rpc_call(
                b"x" * (server.MAX_MSG_SIZE + 1)
            )
        self.assertEqual(ctx.exception.code, 1)


class TestHandshakeTimeoutStateGuard(_TrayFixture):
    """__handshake_timeout kicks only a still-connected, unnamed client."""

    def test_disconnected_unnamed_not_kicked(self) -> None:
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.client_socket.state = lambda: QLocalSocket.UnconnectedState
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))
        client._SdwdateGuiClient__handshake_timeout()
        self.assertEqual(kicked, [])


class _StatusClient(types.SimpleNamespace):
    """Minimal stand-in carrying just the attributes set_tray_icon reads."""


class TestTrayIconWorstStatus(_TrayFixture):
    """set_tray_icon picks the worst sdwdate/Tor status across clients."""

    def _capture_icon(self) -> list:
        captured: list = []
        self.tray.setIcon = lambda icon: captured.append(icon)  # type: ignore
        return captured

    def _client(self, sdw: "server.SdwdateStatus",
                tor: "server.TorStatus") -> _StatusClient:
        return _StatusClient(sdwdate_status=sdw, tor_status=tor)

    def test_single_success_sets_success_icon(self) -> None:
        self.tray.client_list = [
            self._client(server.SdwdateStatus.SUCCESS, server.TorStatus.ABSENT)
        ]
        captured = self._capture_icon()
        self.tray.set_tray_icon()
        self.assertEqual(len(captured), 1)
        self.assertIs(
            captured[0],
            self.tray.sdwdate_icon_list[server.SdwdateStatus.SUCCESS.value],
        )

    def test_worst_sdwdate_status_wins(self) -> None:
        self.tray.client_list = [
            self._client(server.SdwdateStatus.SUCCESS, server.TorStatus.ABSENT),
            self._client(server.SdwdateStatus.ERROR, server.TorStatus.ABSENT),
        ]
        captured = self._capture_icon()
        self.tray.set_tray_icon()
        self.assertIs(
            captured[-1],
            self.tray.sdwdate_icon_list[server.SdwdateStatus.ERROR.value],
        )

    def test_tor_stopped_takes_priority(self) -> None:
        self.tray.client_list = [
            self._client(server.SdwdateStatus.SUCCESS, server.TorStatus.STOPPED)
        ]
        captured = self._capture_icon()
        self.tray.set_tray_icon()
        self.assertIs(
            captured[-1],
            self.tray.tor_icon_list[server.TorStatus.STOPPED.value],
        )

    def test_tor_disabled_takes_priority(self) -> None:
        ## DISABLED (value 3) is the highest Tor status and, like STOPPED, must
        ## override a healthy sdwdate status in the tray -- a disabled Tor is an
        ## outage to surface, not to hide behind a SUCCESS icon. Pins DISABLED in
        ## the priority tuple at set_tray_icon (dropping it hides the outage).
        self.tray.client_list = [
            self._client(server.SdwdateStatus.SUCCESS, server.TorStatus.DISABLED)
        ]
        captured = self._capture_icon()
        self.tray.set_tray_icon()
        self.assertIs(
            captured[-1],
            self.tray.tor_icon_list[server.TorStatus.DISABLED.value],
        )

    def test_all_unknown_sets_no_icon(self) -> None:
        self.tray.client_list = [
            self._client(server.SdwdateStatus.UNKNOWN, server.TorStatus.ABSENT)
        ]
        captured = self._capture_icon()
        self.tray.set_tray_icon()
        self.assertEqual(captured, [])


class TestRegenMenuFilter(_TrayFixture):
    """regen_menu client filter, Tor entries, and empty placeholder."""

    _PLACEHOLDER = "Waiting for sdwdate-gui client..."

    def _ready_client(self, name: str, sdw: "server.SdwdateStatus",
                      tor: "server.TorStatus") -> "server.SdwdateGuiClient":
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_name = name
        client.client_name_set = True
        client.sdwdate_status = sdw
        client.tor_status = tor
        return client

    def _menu_texts(self) -> list[str]:
        texts: list[str] = []
        for action in self.tray.menu_action_list:
            texts.append(action.text())
        return texts

    def test_empty_shows_placeholder(self) -> None:
        self.tray.client_list = []
        self.tray.regen_menu(force_regen=True)
        self.assertIn(self._PLACEHOLDER, self._menu_texts())

    def test_ready_client_no_placeholder_no_tor_entries(self) -> None:
        self.tray.client_list = [
            self._ready_client(
                "vm1", server.SdwdateStatus.SUCCESS, server.TorStatus.ABSENT
            )
        ]
        self.tray.regen_menu(force_regen=True)
        texts = self._menu_texts()
        self.assertNotIn(self._PLACEHOLDER, texts)
        ## Tor-absent client: no Tor menu entries.
        self.assertNotIn("Show Tor status", texts)
        ## sdwdate entries ARE present.
        self.assertIn("Show sdwdate status", texts)

    def test_nameless_client_skipped(self) -> None:
        ## name None -> skipped even though its statuses are set; alone -> the
        ## placeholder appears (pins the `name is None or (...)` filter).
        client = self._ready_client(
            "ignored", server.SdwdateStatus.SUCCESS, server.TorStatus.ABSENT
        )
        client.client_name = None
        client.client_name_set = False
        self.tray.client_list = [client]
        self.tray.regen_menu(force_regen=True)
        self.assertIn(self._PLACEHOLDER, self._menu_texts())

    def test_partial_unknown_client_shown(self) -> None:
        ## tor UNKNOWN but sdwdate known -> NOT "both unknown", so shown.
        ## Pins the `and` in the readiness check against `or`.
        self.tray.client_list = [
            self._ready_client(
                "vm2", server.SdwdateStatus.SUCCESS, server.TorStatus.UNKNOWN
            )
        ]
        self.tray.regen_menu(force_regen=True)
        self.assertNotIn(self._PLACEHOLDER, self._menu_texts())

    def test_tor_enabled_client_has_tor_entries(self) -> None:
        self.tray.client_list = [
            self._ready_client(
                "vm3", server.SdwdateStatus.SUCCESS, server.TorStatus.RUNNING
            )
        ]
        self.tray.regen_menu(force_regen=True)
        self.assertIn("Show Tor status", self._menu_texts())


if __name__ == "__main__":
    unittest.main()
