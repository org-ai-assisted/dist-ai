#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression tests for sdwdate-gui-server wire-protocol and client-list
defects found by the simulator / fuzzer (sdwdate_gui_fuzzer.py):

  * an incomplete (fragmented) command must not hang the parser,
  * a newline in a status message must not get the client kicked,
  * drop_client must be idempotent (a kick legitimately drops a client
    twice) without a spurious "not present" warning,
  * status escape decoding must be a single deterministic pass (not a
    hash-order-dependent sequence of global replacements),
  * an attacker-controlled status message must not inject markup into the
    rich-text status window.

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

from PyQt5.QtCore import QObject, pyqtSignal
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

    The fix routes the message through helper-scripts sanitize_string()
    (strips markup, ANSI / control characters and all non-ASCII) and then
    html.escape() (neutralises any residual rich-text metacharacter). Note
    the wire protocol already restricts a status message to printable
    ASCII, so the non-ASCII handling here is defense in depth: it covers
    the display path regardless of how the message was set.
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
        """Markup and unsafe characters are removed from the status window."""
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

        rendered = " ".join(
            label.text() for label in self.tray.msg_window.findChildren(QLabel)
        )
        self.assertIn("SAFE", rendered)
        ## The markup tag is gone (stripped, not rendered).
        self.assertNotIn("<img", rendered)
        self.assertNotIn("onerror", rendered)
        ## A residual lone metacharacter is escaped, not left bare.
        self.assertIn("&lt;", rendered)
        ## Non-ASCII confusables are removed.
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("\u200b", rendered)


class DropClientTests(unittest.TestCase):
    """drop_client must be idempotent without a spurious warning (Bug C)."""

    def setUp(self) -> None:
        self._real_listener = server.SdwdateGuiListener
        server.SdwdateGuiListener = _FakeListener
        self.tray = server.SdwdateTrayIcon()

    def tearDown(self) -> None:
        server.SdwdateGuiListener = self._real_listener
        self.tray.deleteLater()
        _APP.processEvents()

    def test_double_drop_is_quiet_noop(self) -> None:
        """Dropping the same client twice is a quiet no-op."""
        client = server.SdwdateGuiClient(QLocalSocket())
        self.tray.accept_client(client)
        client.client_name = "disp5711"
        client.client_name_set = True
        client.sdwdate_status = server.SdwdateStatus.SUCCESS
        client.tor_status = server.TorStatus.ABSENT

        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = records.append  # type: ignore[method-assign]
        logging.getLogger().addHandler(handler)
        try:
            self.tray.drop_client(client)  # first drop: removes it
            self.tray.drop_client(client)  # second drop: quiet no-op
        finally:
            logging.getLogger().removeHandler(handler)

        self.assertNotIn(client, self.tray.client_list)
        self.assertFalse(
            any(
                "not present in client list" in record.getMessage()
                for record in records
            )
        )
        self.assertTrue(client.dropped)


if __name__ == "__main__":
    unittest.main()
