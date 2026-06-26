#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate-gui-server wire-protocol and client-list
defects found by the simulator / fuzzer (sdwdate_gui_fuzzer.py):

  * an incomplete (fragmented) command must not hang the parser,
  * a newline in a status message must not get the client kicked,
  * a kick must drop a client exactly once (kick_client disconnects the
    socket's disconnected() signal so clientDisconnected fires once),
  * status escape decoding must be a single deterministic pass (not a
    hash-order-dependent sequence of global replacements),
  * an attacker-controlled status message cannot inject markup: it is
    sanitized and shown in a plain-text (not rich-text) status window,
  * untrusted strings are bounded to reasonable lengths: the qrexec header
    name, the message shown in the status window, and the message the
    client sends (also ASCII-coerced).

These drive the real SdwdateGuiClient / SdwdateTrayIcon under the Qt
offscreen platform plugin; no X server or qrexec is required.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access

import contextlib
import logging
import os
import signal
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import Qt, QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    raise unittest.SkipTest(
        "sdwdate-gui is not importable; install the 'sdwdate-gui' package "
        "or set PYTHONPATH to its dist-packages directory"
    ) from exc


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


class _FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub for SdwdateGuiListener; avoids PID-file / socket side effects."""

    newClient = pyqtSignal(object)


def _named_client() -> server.SdwdateGuiClient:
    """A server-side client past the qrexec header with a name set."""
    client = server.SdwdateGuiClient(QLocalSocket())
    client.qubes_header_parsed = True
    client.client_name = "disp5711"
    client.client_name_set = True
    return client


class IncompleteMessageTests(unittest.TestCase):
    """An incomplete message must not spin the parser forever (Bug A)."""

    def test_incomplete_message_does_not_hang(self) -> None:
        """An incomplete message returns instead of looping forever."""
        client = _named_client()
        ## Length prefix claims 100 bytes, only 5 are present.
        client._SdwdateGuiClient__sock_buf = b"\x00\x64short"
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))

        with watchdog(2.0):
            client._SdwdateGuiClient__try_parse_commands()

        ## Not kicked (incomplete is not invalid), and the partial message is
        ## kept in the buffer to await the rest.
        self.assertEqual(kicked, [])
        self.assertEqual(client._SdwdateGuiClient__sock_buf, b"\x00\x64short")


class NewlineStatusTests(unittest.TestCase):
    """A newline in a status message must be accepted (Bug B)."""

    def test_newline_status_not_kicked(self) -> None:
        """A status message containing a newline is accepted."""
        client = _named_client()
        payload = b"set_sdwdate_status success a\\012b"  # \012 = newline
        client._SdwdateGuiClient__sock_buf = len(payload).to_bytes(2, "big") + payload
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))

        client._SdwdateGuiClient__try_parse_commands()

        self.assertEqual(kicked, [])
        self.assertEqual(client.sdwdate_msg, "a\nb")


def _encode_status_msg(text: str) -> bytes:
    """Encode a status message exactly as sdwdate_gui_client does."""
    out = text.replace("\\", "\\134").replace(" ", "\\040")
    return out.replace("\n", "\\012").encode("ascii")


class StatusDecodeTests(unittest.TestCase):
    """Status escape decoding must be deterministic and correct (Bug D)."""

    def test_decode_roundtrip(self) -> None:
        """Escapes decode in a single pass, independent of hash order."""
        ## "\012\134012" on the wire: a newline escape followed by an
        ## escaped backslash and the literal "012". A per-escape global
        ## replace would, for some hash seeds, re-decode the formed "\012".
        for text in ["line\nbreak", "\n\\012", "x\\134\\012y", "end \\040"]:
            client = _named_client()
            payload = b"set_sdwdate_status success " + _encode_status_msg(text)
            client._SdwdateGuiClient__sock_buf = (
                len(payload).to_bytes(2, "big") + payload
            )
            kicked: list[bool] = []
            client.clientDisconnected.connect(lambda k=kicked: k.append(True))

            client._SdwdateGuiClient__try_parse_commands()

            self.assertEqual(kicked, [])
            self.assertEqual(client.sdwdate_msg, text)


class StatusMarkupEscapeTests(unittest.TestCase):
    """A client status message must not inject markup into the GUI (Bug E).

    The status windows render as plain text (not rich text), and untrusted
    text is routed through helper-scripts sanitize_string() (strips markup,
    ANSI / control characters and all non-ASCII). The wire already restricts
    a status message to printable ASCII, so the non-ASCII handling here is
    defense in depth: it covers the display path regardless of how the
    message was set.
    """

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

    def test_status_message_is_sanitized(self) -> None:
        """Markup and unsafe characters cannot reach the status window."""
        from PyQt5.QtWidgets import (  # pylint: disable=import-outside-toplevel
            QLabel,
        )

        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.client_name = "vm"
        client.client_name_set = True
        client.sdwdate_status = server.SdwdateStatus.SUCCESS
        client.tor_status = server.TorStatus.ABSENT
        ## Markup, a lone metacharacter, a right-to-left override
        ## (\u202e) and a zero-width space (\u200b). Set directly: the
        ## wire would reject non-ASCII, so this exercises the display-layer
        ## sanitization itself (defense in depth).
        client.sdwdate_msg = "<img src=x onerror=1>SAFE plain < amp \u202e zw\u200b"
        ## show_status_msg refuses a disconnected client; make the socket
        ## report as connected for this white-box check.
        client.client_socket.state = lambda: QLocalSocket.ConnectedState

        self.tray.show_status_msg(server.MessageType.SDWDATE, client)

        labels = self.tray.msg_window.findChildren(QLabel)
        rendered = " ".join(label.text() for label in labels)
        ## The dialog renders as plain text, so injected markup cannot be
        ## interpreted as HTML even if a residual metacharacter survives.
        self.assertTrue(
            all(label.textFormat() == Qt.TextFormat.PlainText for label in labels)
        )
        self.assertIn("SAFE", rendered)
        ## sanitize_string strips the markup tag and the non-ASCII confusables.
        self.assertNotIn("<img", rendered)
        self.assertNotIn("onerror", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u200b", rendered)

    def test_client_name_sanitized_at_input(self) -> None:
        """A name with markup is sanitized when set, not at display time."""
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client._SdwdateGuiClient__set_client_name("ab<b>cd")
        self.assertEqual(client.client_name, "abcd")


class DropClientTests(unittest.TestCase):
    """A kick must not drop a client twice (Bug C, root fix in kick_client)."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self._real_in_qubes = server.running_in_qubes_os
        server.running_in_qubes_os = lambda: False
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_in_qubes
        self.tray.deleteLater()
        _APP.processEvents()

    def test_kick_emits_disconnect_once(self) -> None:
        """kick_client fires clientDisconnected exactly once, dropping once."""
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.client_name = "disp5711"
        client.client_name_set = True
        client.sdwdate_status = server.SdwdateStatus.SUCCESS
        client.tor_status = server.TorStatus.ABSENT

        fired: list[bool] = []
        client.clientDisconnected.connect(lambda: fired.append(True))

        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = records.append  # type: ignore[method-assign]
        logging.getLogger().addHandler(handler)
        try:
            client.kick_client()
        finally:
            logging.getLogger().removeHandler(handler)

        ## kick_client disconnects the socket's disconnected() signal before
        ## emitting, so clientDisconnected -> drop_client fires exactly once
        ## and there is no spurious "not present" warning.
        self.assertEqual(fired, [True])
        self.assertNotIn(client, self.tray.client_list)
        self.assertFalse(
            any(
                "not present in client list" in record.getMessage()
                for record in records
            )
        )


class LengthCapTests(unittest.TestCase):
    """Untrusted strings are bounded to reasonable lengths."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self._real_in_qubes = server.running_in_qubes_os
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_in_qubes
        if self.tray.msg_window is not None:
            self.tray.msg_window.close()
        self.tray.deleteLater()
        _APP.processEvents()

    def test_qubes_header_name_length_capped(self) -> None:
        """An over-long qrexec header name is rejected; a valid one is kept."""
        server.running_in_qubes_os = lambda: True

        ok_client = server.SdwdateGuiClient(QLocalSocket())
        ok_client.qubes_header_parsed = False
        ok_client._SdwdateGuiClient__sock_buf = (
            b"sdwdate-gui.Connect " + b"a" * server.MAX_QUBES_NAME_LEN + b"\0"
        )
        self.assertTrue(ok_client._SdwdateGuiClient__parse_qubes_data())
        self.assertEqual(ok_client.client_name, "a" * server.MAX_QUBES_NAME_LEN)

        long_client = server.SdwdateGuiClient(QLocalSocket())
        kicked: list[bool] = []
        long_client.clientDisconnected.connect(lambda: kicked.append(True))
        long_client._SdwdateGuiClient__sock_buf = (
            b"sdwdate-gui.Connect " + b"a" * (server.MAX_QUBES_NAME_LEN + 1) + b"\0"
        )
        long_client._SdwdateGuiClient__parse_qubes_data()
        self.assertEqual(kicked, [True])
        self.assertIsNone(long_client.client_name)

    def test_status_message_display_truncated(self) -> None:
        """A long status message is truncated in the status window."""
        from PyQt5.QtWidgets import (  # pylint: disable=import-outside-toplevel
            QLabel,
        )

        server.running_in_qubes_os = lambda: False
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.client_name = "vm"
        client.client_name_set = True
        client.sdwdate_status = server.SdwdateStatus.SUCCESS
        client.tor_status = server.TorStatus.ABSENT
        client.sdwdate_msg = "X" * 5000
        client.client_socket.state = lambda: QLocalSocket.ConnectedState

        self.tray.show_status_msg(server.MessageType.SDWDATE, client)

        rendered = " ".join(
            label.text() for label in self.tray.msg_window.findChildren(QLabel)
        )
        self.assertEqual(rendered.count("X"), server.MAX_DISPLAY_MSG_LEN)


class ResourceLimitTests(unittest.TestCase):
    """Connection count and client handshake lifetime are bounded."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        ## Force non-Qubes so kick_client() does not take the Qubes
        ## suppress-reconnect write path (which would spin on the dead
        ## unconnected test socket whose state() is mocked as connected).
        self._real_in_qubes = server.running_in_qubes_os
        server.running_in_qubes_os = lambda: False
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        server.running_in_qubes_os = self._real_in_qubes
        self.tray.deleteLater()
        _APP.processEvents()

    def test_connection_cap_enforced(self) -> None:
        """accept_client rejects connections beyond MAX_CLIENTS."""
        for _ in range(server.MAX_CLIENTS + 5):
            self.tray.accept_client(server.SdwdateGuiClient(QLocalSocket()))
        self.assertEqual(len(self.tray.client_list), server.MAX_CLIENTS)

    def test_handshake_timeout_kicks_unnamed_only(self) -> None:
        """The handshake timeout kicks a nameless client, not a named one."""
        unnamed = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(unnamed)
        unnamed.client_socket.state = lambda: QLocalSocket.ConnectedState
        kicked: list[bool] = []
        unnamed.clientDisconnected.connect(lambda: kicked.append(True))
        unnamed._SdwdateGuiClient__handshake_timeout()
        self.assertEqual(kicked, [True])

        named = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(named)
        named.client_name = "vm"
        named.client_name_set = True
        named.client_socket.state = lambda: QLocalSocket.ConnectedState
        named_kicked: list[bool] = []
        named.clientDisconnected.connect(lambda: named_kicked.append(True))
        named._SdwdateGuiClient__handshake_timeout()
        self.assertEqual(named_kicked, [])

    def test_generic_rpc_call_kicks_on_write_error(self) -> None:
        """__generic_rpc_call kicks the client on a write error (write < 0)."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState
        client.client_socket.write = lambda _data: -1  # error
        kicked: list[bool] = []
        client.clientDisconnected.connect(lambda: kicked.append(True))

        ## setUp forces non-Qubes, so kick_client() does not re-enter via
        ## suppress_client_reconnect(); the watchdog catches a hang regardless.
        with watchdog(2.0):
            client._SdwdateGuiClient__generic_rpc_call(b"restart_sdwdate")
        self.assertEqual(kicked, [True])

    @unittest.skip(
        "Known upstream bug (Kicksecure/sdwdate-gui): on Qubes a write "
        "error recurses kick_client() -> suppress_client_reconnect() -> "
        "__generic_rpc_call() -> kick_client(). Un-skip once the maintainer "
        "guards kick_client against re-entrancy or stops kicking from the "
        "send loop."
    )
    def test_write_error_no_recursion_on_qubes(self) -> None:
        """On Qubes a write error must not recurse via suppress-reconnect."""
        server.running_in_qubes_os = lambda: True
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState
        client.client_socket.write = lambda _data: -1
        with watchdog(2.0):
            client._SdwdateGuiClient__generic_rpc_call(b"restart_sdwdate")

    def test_server_refuses_oversized_rpc(self) -> None:
        """__generic_rpc_call exits on a message above the frame limit."""
        client = server.SdwdateGuiClient(QLocalSocket())
        client.client_socket.state = lambda: QLocalSocket.ConnectedState
        with self.assertRaises(SystemExit):
            client._SdwdateGuiClient__generic_rpc_call(b"x" * (server.MAX_MSG_SIZE + 1))


class ClientSendTests(unittest.TestCase):
    """The client bounds and ASCII-coerces what it sends (Bug, audit)."""

    def test_status_message_capped_and_ascii(self) -> None:
        """A long / non-ASCII status message is capped and ASCII-coerced."""
        import asyncio  # pylint: disable=import-outside-toplevel

        try:
            from sdwdate_gui import (  # pylint: disable=import-outside-toplevel
                sdwdate_gui_client as client,
            )
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise unittest.SkipTest("sdwdate-gui client not importable") from exc

        sent: dict = {}

        async def fake_rpc(msg_bytes: bytes) -> None:
            sent["bytes"] = msg_bytes

        real_rpc = client.generic_rpc_call
        client.generic_rpc_call = fake_rpc
        try:
            asyncio.run(client.set_sdwdate_status("success", "A" * 5000 + "\u00e9end"))
        finally:
            client.generic_rpc_call = real_rpc

        payload = sent["bytes"]
        ## Fits the server's 4096-byte frame, never overflows the 2-byte
        ## length prefix, and carries only ASCII bytes.
        self.assertLess(len(payload), 4096)
        self.assertTrue(payload.isascii())

    def test_oversized_message_exits(self) -> None:
        """generic_rpc_call exits on a message above the frame limit."""
        import asyncio  # pylint: disable=import-outside-toplevel

        try:
            from sdwdate_gui import (  # pylint: disable=import-outside-toplevel
                sdwdate_gui_client as client,
            )
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise unittest.SkipTest("sdwdate-gui client not importable") from exc

        class FakeWriter:  # pylint: disable=too-few-public-methods
            """Minimal stand-in for the asyncio StreamWriter."""

            def write(self, data: bytes) -> None:
                """No-op write."""

            async def drain(self) -> None:
                """No-op flush."""

        client.GlobalData.sock_write = FakeWriter()
        with self.assertRaises(SystemExit):
            asyncio.run(client.generic_rpc_call(b"x" * (client.MAX_MSG_SIZE + 1)))

    def test_launchers_spawn_via_asyncio(self) -> None:
        """RPC launchers spawn via asyncio (auto-reaped), not Popen."""
        import asyncio  # pylint: disable=import-outside-toplevel

        try:
            from sdwdate_gui import (  # pylint: disable=import-outside-toplevel
                sdwdate_gui_client as client,
            )
        except ModuleNotFoundError as exc:  # pragma: no cover
            raise unittest.SkipTest("sdwdate-gui client not importable") from exc

        calls: list[tuple] = []

        class FakeProc:  # pylint: disable=too-few-public-methods
            """Stand-in process whose wait() the launcher awaits."""

            async def wait(self) -> int:
                """Report immediate, clean exit."""
                return 0

        async def fake_exec(*args: str) -> "FakeProc":
            calls.append(args)
            return FakeProc()

        real = asyncio.create_subprocess_exec
        asyncio.create_subprocess_exec = fake_exec
        try:
            asyncio.run(client.restart_sdwdate())
            asyncio.run(client.stop_sdwdate())
        finally:
            asyncio.create_subprocess_exec = real

        self.assertEqual(
            calls,
            [("leaprun", "sdwdate-clock-jump"), ("leaprun", "stop-sdwdate")],
        )


if __name__ == "__main__":
    unittest.main()
