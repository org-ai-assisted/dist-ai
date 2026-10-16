#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Regression guards for upstream sdwdate-gui bugs fixed by ArrayBolt3.

Each test asserts the FIXED behavior and must PASS against the current subject;
a failure means the fix regressed. Each names its org-ai-assisted/sdwdate-gui
issue.

Guarded (fixed):
  - #11 multi-client Tor-status aggregation: a STOPPED/DISABLED client's Tor
    icon is shown and not masked by a DISABLED_RUNNING client (fixed by
    reordering the TorStatus enum + icon list so STOPPED/DISABLED outrank
    DISABLED_RUNNING under the numeric-max aggregation).
  - #13 client reconnect buffer reset: do_setup() clears GlobalData.sock_buf so
    residual bytes from a mid-command disconnect cannot wedge the next session.

Open (xfail guards):
  - #16 (a NUL waives the >4096 qrexec-header cap), #17 (__parse_qubes_data
    returns True after kicking an invalid header name), and #18 (a failed octal
    escape commits the new sdwdate status but keeps the old message) are proven,
    filed, and NOT yet fixed upstream. Each guard asserts the FIXED behavior and
    is marked @expectedFailure: it FAILS against the current (buggy) subject (an
    expected failure, suite stays green) and FLIPS to an unexpected success --
    turning the suite RED -- the moment ArrayBolt3's fix lands, which is the
    signal to convert the guard into a plain passing regression test.

Not guarded here:
  - #10 (control chars in a status message) and #14 (a hostname with a space or
    control character) are kicked BY DESIGN per the maintainer -- see the
    subject's AGENTS.md "By design" section. They are not bugs; no guard.
  - #12 (ConnectCheck ignoring run_server_in_qubes) has no in-suite guard: its
    bash script hardcodes its /run and config-read paths with no overridable
    base and exposes no source-able function, so it cannot be driven without a
    synthetic copy (forbidden by the dist-ai no-synthetic-copies rule) or a
    non-portable mount namespace, and nothing else runs it (no integration
    responder, not covered by kcov). Tracked by org-ai-assisted/sdwdate-gui#12.

All tests import and drive the REAL subject functions -- no vendored copies.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access
# pylint: disable=invalid-name,import-outside-toplevel

import asyncio
import os
import unittest
import unittest.mock as mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_client as client
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard

    subject_guard.skip_if_subject_absent(exc)

_APP = QApplication.instance() or QApplication(["bug-regressions"])


def _frame(body: bytes) -> bytes:
    """Length-prefix a body as the client's generic_rpc_call does."""
    return len(body).to_bytes(2, byteorder="big", signed=False) + body


class TorStatusAggregation(unittest.TestCase):
    """Issue #11: a STOPPED/DISABLED Tor outage must not be hidden behind a
    DISABLED_RUNNING client."""

    def test_issue11_tor_outage_not_hidden_by_disabled_running(self) -> None:
        """org-ai-assisted/sdwdate-gui#11 -- regression guard (must pass)."""
        tor_status = server.TorStatus
        sdwdate_status = server.SdwdateStatus

        class _Client:  # pylint: disable=too-few-public-methods
            def __init__(self, tor) -> None:
                self.tor_status = tor
                self.sdwdate_status = sdwdate_status.SUCCESS

        set_icons: list = []

        class _Tray:  # pylint: disable=too-few-public-methods
            ## Recognizable stand-ins for the real QIcon lists; the first tuple
            ## element identifies which list the chosen icon came from, the
            ## second its index.
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
        ## The STOPPED client's Tor icon must be selected SPECIFICALLY (its own
        ## index), not merely "a Tor icon": with the reordered enum STOPPED
        ## outranks DISABLED_RUNNING under the numeric-max aggregation, so its
        ## outage is shown rather than masked.
        self.assertEqual(
            set_icons[-1],
            ("tor", tor_status.STOPPED.value),
            "STOPPED Tor outage not shown (hidden behind DISABLED_RUNNING)",
        )


class ClientReconnectBufferReset(unittest.TestCase):
    """Issue #13: do_setup() resets GlobalData.sock_buf on (re)connect so a
    residual partial frame cannot wedge the next session."""

    def setUp(self) -> None:
        self._saved_buf = client.GlobalData.sock_buf
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        client.GlobalData.sock_buf = self._saved_buf

    def test_issue13_do_setup_resets_sock_buf(self) -> None:
        """org-ai-assisted/sdwdate-gui#13 -- regression guard (must pass)."""
        ## Residual partial frame left by a dropped session.
        client.GlobalData.sock_buf = _frame(b"set") + b"EXTRA"

        async def run() -> None:
            ## open_connection failing returns do_setup early, AFTER its
            ## buffer reset -- which is all this guard checks.
            with mock.patch.object(
                client,
                "open_connection",
                new=mock.AsyncMock(return_value=False),
            ):
                await client.do_setup()

        asyncio.run(run())
        self.assertEqual(
            client.GlobalData.sock_buf,
            b"",
            "sock_buf not reset on (re)connect; residual wedges next session",
        )


class OpenUpstreamBugGuards(unittest.TestCase):
    """xfail guards for filed-but-unfixed subject bugs (#16/#17/#18).

    Each drives the REAL server handler and asserts the FIXED behavior. Marked
    @expectedFailure: expected to FAIL on the current buggy subject; a flip to
    unexpectedSuccess fails the suite and signals the upstream fix landed.
    """

    def setUp(self) -> None:
        self._real_qubes = server.running_in_qubes_os
        self.addCleanup(self._restore_qubes)
        self.cli = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(self.cli.deleteLater)

    def _restore_qubes(self) -> None:
        server.running_in_qubes_os = self._real_qubes

    @staticmethod
    def _set_qubes(value: bool) -> None:
        server.running_in_qubes_os = lambda: value

    def _mangled(self, name: str):
        return getattr(self.cli, f"_SdwdateGuiClient__{name}")

    @unittest.expectedFailure
    def test_issue16_nul_does_not_waive_header_cap(self) -> None:
        """org-ai-assisted/sdwdate-gui#16 -- xfail until fixed.

        An oversized printable prefix followed by a NUL must be kicked just
        like an oversized no-NUL buffer. Today the >4096 cap sits only in the
        no-NUL branch, so the NUL form is accepted (kick not called).
        """
        self._set_qubes(True)
        self.cli._SdwdateGuiClient__sock_buf = b"A" * 5000 + b" syswhonix\x00"
        with mock.patch.object(self.cli, "kick_client") as kc:
            self._mangled("parse_qubes_data")()
        kc.assert_called_once()

    @unittest.expectedFailure
    def test_issue17_invalid_header_name_returns_false(self) -> None:
        """org-ai-assisted/sdwdate-gui#17 -- xfail until fixed.

        When the qrexec header name is invalid, __set_client_name kicks and
        returns False; __parse_qubes_data must propagate that False so the
        caller does not parse the tail on a kicked client. Today it returns
        True regardless.
        """
        self._set_qubes(True)
        self.cli._SdwdateGuiClient__sock_buf = b"svc 9bad\x00"
        with mock.patch.object(self.cli, "kick_client"):
            result = self._mangled("parse_qubes_data")()
        self.assertFalse(
            result,
            "parse_qubes_data returned True after an invalid-name kick",
        )

    @unittest.expectedFailure
    def test_issue18_failed_octal_decode_does_not_commit_status(self) -> None:
        """org-ai-assisted/sdwdate-gui#18 -- xfail until fixed.

        A set_sdwdate_status whose message has an unsafe octal escape must
        leave the prior status AND message untouched. Today the status is
        committed before the decode, so a failed decode mutates status while
        the message stays stale.
        """
        self.cli.client_name = "host"
        self.cli.client_name_set = True
        ok = self._mangled("set_sdwdate_status")("success", "hello")
        self.assertTrue(ok)
        self.assertEqual(self.cli.sdwdate_status, server.SdwdateStatus.SUCCESS)
        with mock.patch.object(self.cli, "kick_client"):
            self._mangled("set_sdwdate_status")("error", "\\777")
        ## Fixed behavior: a rejected update is atomic -- status unchanged.
        self.assertEqual(
            self.cli.sdwdate_status,
            server.SdwdateStatus.SUCCESS,
            "status committed despite the failed octal decode",
        )


if __name__ == "__main__":
    unittest.main()
