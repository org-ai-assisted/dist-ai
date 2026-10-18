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
  - #16 the >4096 qrexec-header cap applies to the pre-NUL header too, so a NUL
    no longer waives it (fixed in 2fe70059).
  - #17 __parse_qubes_data propagates __set_client_name's result, so a client
    kicked for an invalid header name returns False and its tail is not parsed
    (fixed in 09fdc1ac).

Not guarded here:
  - #10 (control chars in a status message), #14 (a hostname with a space or
    control character), and #18 (a failed octal escape leaves a kicked client's
    status/message inconsistent) are BY DESIGN per the maintainer -- see the
    subject's AGENTS.md "By design" section. Not bugs; no guard. #18's bad-octal
    rejection itself (kick + False) is covered by test_octal_decode_exhaustive.
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


class LandedUpstreamFixGuards(unittest.TestCase):
    """Regression guards for ArrayBolt3's landed fixes (#16, #17).

    Each drives the REAL server handler and asserts the FIXED behavior; it must
    PASS against the current subject, and a failure means the fix regressed.
    Every guard pins BOTH the fixed bug AND the surrounding correct behavior, so
    a later refactor reintroducing a plausible WRONG shape (an off-by-one cap, a
    blanket early return) still fails.
    """

    def setUp(self) -> None:
        self._real_qubes = server.running_in_qubes_os
        self.addCleanup(self._restore_qubes)

    def _restore_qubes(self) -> None:
        server.running_in_qubes_os = self._real_qubes

    @staticmethod
    def _set_qubes(value: bool) -> None:
        server.running_in_qubes_os = lambda: value

    def _fresh(self) -> "server.SdwdateGuiClient":
        cli = server.SdwdateGuiClient(QLocalSocket())
        self.addCleanup(cli.deleteLater)
        return cli

    @staticmethod
    def _parse(cli: "server.SdwdateGuiClient", buf: bytes) -> bool:
        cli._SdwdateGuiClient__sock_buf = buf
        return getattr(cli, "_SdwdateGuiClient__parse_qubes_data")()

    def test_issue16_nul_does_not_waive_header_cap(self) -> None:
        """org-ai-assisted/sdwdate-gui#16 -- regression guard (fixed 2fe70059).

        The >4096 cap must apply to the pre-NUL header too. Pinned so a later
        wrong refactor still fails: (a) the oversize is in a NON-service field
        and the kicked parse must return False with no name (rules out a 'reject
        long service name' or 'kick but still return True' shape); (b) an
        ordinary header must NOT be kicked (rules out 'kick any NUL buffer');
        (c) a pre-NUL header of exactly 4096 bytes must be accepted (rules out a
        '>=4096' off-by-one).
        """
        self._set_qubes(True)
        ## (a) 5000+ bytes of excess AFTER a valid name -> must be kicked, and
        ##     the parse must report failure so no tail is processed.
        cli = self._fresh()
        with mock.patch.object(cli, "kick_client") as kc:
            result = self._parse(cli, b"svc syswhonix " + b"A" * 5000 + b"\x00")
        self.assertTrue(kc.called, "oversized pre-NUL header not kicked")
        self.assertFalse(result, "kicked header still returned True")
        self.assertFalse(cli.client_name_set, "name set on a kicked header")
        ## (b) an ordinary header must pass untouched.
        cli = self._fresh()
        with mock.patch.object(cli, "kick_client") as kc:
            result = self._parse(cli, b"svc syswhonix\x00")
        self.assertFalse(kc.called, "ordinary header wrongly kicked")
        self.assertTrue(result)
        self.assertTrue(cli.client_name_set)
        ## (c) exactly 4096 pre-NUL bytes must be accepted (cap is > not >=).
        cli = self._fresh()
        header_4096 = b"A" * 4086 + b" syswhonix"
        self.assertEqual(len(header_4096), 4096)
        with mock.patch.object(cli, "kick_client") as kc:
            self._parse(cli, header_4096 + b"\x00")
        self.assertFalse(kc.called, "a 4096-byte header was kicked (>= not >)")

    def test_issue17_invalid_header_name_returns_false(self) -> None:
        """org-ai-assisted/sdwdate-gui#17 -- regression guard (fixed 09fdc1ac).

        __parse_qubes_data must propagate __set_client_name's result. Pinned so
        a later wrong refactor still fails: an invalid name (a RESERVED name,
        not merely digit-leading) must both kick AND return False, while a VALID
        name must still return True with the name set -- ruling out both a
        'special-case digit names' shape and a blanket 'return False'.
        """
        self._set_qubes(True)
        ## invalid (reserved) name: must kick and report failure.
        cli = self._fresh()
        with mock.patch.object(cli, "kick_client") as kc:
            result = self._parse(cli, b"svc default\x00")
        self.assertTrue(kc.called, "invalid header name did not kick")
        self.assertFalse(
            result, "parse_qubes_data returned True after an invalid-name kick"
        )
        ## valid name: must still succeed (rules out a blanket return False).
        cli = self._fresh()
        with mock.patch.object(cli, "kick_client") as kc:
            result = self._parse(cli, b"svc syswhonix\x00")
        self.assertFalse(kc.called)
        self.assertTrue(result, "a valid header name no longer returns True")
        self.assertTrue(cli.client_name_set)


if __name__ == "__main__":
    unittest.main()
