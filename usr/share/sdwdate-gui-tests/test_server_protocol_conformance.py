#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
State-sequence conformance fuzz of the sdwdate-gui SERVER per-client command
protocol against an independent reference model.

The example-based wire-protocol tests each pin ONE ordering. This drives the
REAL SdwdateGuiClient (Qubes mode pinned, mocked QLocalSocket) through RANDOM
sequences of a header event plus command / handshake-timeout events, and
asserts its observable state -- kicked, named, status, message -- matches a
hand-derived reference model of the protocol. A divergence (a sequence the
server accepts but the model rejects, a missed or spurious kick, or a wrong
status on a live client) is a real protocol bug that single-ordering tests
cannot surface.

Scope note: on Qubes the client identity is a dom0-stamped qrexec header that
always precedes any client data, so every sequence begins with exactly one
header event; the randomized part is the command ordering after it.
"""

# pylint: disable=wrong-import-position,no-name-in-module,protected-access
# pylint: disable=invalid-name

import os
import unittest
import unittest.mock as mock

from hypothesis import given, settings
from hypothesis import strategies as st

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtNetwork import QLocalSocket
from PyQt5.QtWidgets import QApplication

try:
    from sdwdate_gui import sdwdate_gui_server as server
except ModuleNotFoundError as exc:  # pragma: no cover
    import subject_guard  # pylint: disable=import-outside-toplevel

    subject_guard.skip_if_subject_absent(exc)

_APP = QApplication.instance() or QApplication(["conformance"])

## --- Event alphabet --------------------------------------------------------
## Header variants (exactly one, first). All four are states the server's own
## header parser handles: a 2-token header names the client, a 1-token header
## leaves it alive-but-unnamed, an invalid name or a non-printable byte kicks.
H_VALID = "h_valid"
H_NONAME = "h_noname"
H_INVALID = "h_invalid"
H_NONPRINTABLE = "h_nonprintable"
HEADERS = (H_VALID, H_NONAME, H_INVALID, H_NONPRINTABLE)

## Command / timeout events, any order and count after the header.
C_NAME_VALID = "c_name_valid"
C_NAME_INVALID = "c_name_invalid"
C_STATUS_SUCCESS = "c_status_success"
C_STATUS_BUSY = "c_status_busy"
C_STATUS_BADSTATUS = "c_status_badstatus"
C_STATUS_BADOCTAL = "c_status_badoctal"
C_UNKNOWN = "c_unknown"
C_TIMEOUT = "c_timeout"
COMMANDS = (
    C_NAME_VALID,
    C_NAME_INVALID,
    C_STATUS_SUCCESS,
    C_STATUS_BUSY,
    C_STATUS_BADSTATUS,
    C_STATUS_BADOCTAL,
    C_UNKNOWN,
    C_TIMEOUT,
)

## qrexec stamps "<service> <source-vm>\0"; a 1-token header has no source-vm.
_HEADER_BYTES = {
    H_VALID: b"qubes.SdwdateGui disp1234\x00",
    H_NONAME: b"qubes.SdwdateGui\x00",
    H_INVALID: b"qubes.SdwdateGui 9bad\x00",
    H_NONPRINTABLE: b"qubes.SdwdateGui \x01x\x00",
}


def _frame(body: str) -> bytes:
    """A length-prefixed IPC command frame (2-byte big-endian length + body)."""
    payload: bytes = body.encode("ascii")
    return len(payload).to_bytes(2, byteorder="big", signed=False) + payload


_COMMAND_BYTES = {
    C_NAME_VALID: _frame("set_client_name goodname"),
    C_NAME_INVALID: _frame("set_client_name 9bad"),
    C_STATUS_SUCCESS: _frame("set_sdwdate_status success hello"),
    C_STATUS_BUSY: _frame("set_sdwdate_status busy waiting"),
    C_STATUS_BADSTATUS: _frame("set_sdwdate_status bogus x"),
    C_STATUS_BADOCTAL: _frame("set_sdwdate_status success \\777"),
    C_UNKNOWN: _frame("frobnicate x"),
}

## status enum name + decoded message for the two accepted status updates.
_STATUS_OF = {
    C_STATUS_SUCCESS: ("SUCCESS", "hello"),
    C_STATUS_BUSY: ("BUSY", "waiting"),
}


class _Model:
    """Independent reference of the server per-client protocol (Qubes mode)."""

    def __init__(self, header: str) -> None:
        self.named: bool = False
        self.kicked: bool = False
        self.status: str = "UNKNOWN"
        self.msg: str | None = None
        if header == H_VALID:
            self.named = True
        elif header == H_NONAME:
            pass  ## alive but unnamed
        else:  ## invalid name or non-printable byte in the header
            self.kicked = True

    def step(self, event: str) -> None:
        if self.kicked:
            return  ## socket disconnected; no further data is processed
        if event == C_TIMEOUT:
            ## The handshake timer kicks only a client that never got a name.
            if not self.named:
                self.kicked = True
            return
        if event in (C_NAME_VALID, C_NAME_INVALID):
            if self.named:
                self.kicked = True  ## re-naming is forbidden (checked first)
            elif event == C_NAME_INVALID:
                self.kicked = True  ## invalid name
            else:
                self.named = True
            return
        ## set_sdwdate_status checks name-is-set BEFORE validating the status.
        if not self.named:
            self.kicked = True
            return
        if event in (C_STATUS_SUCCESS, C_STATUS_BUSY):
            self.status, self.msg = _STATUS_OF[event]
        else:
            ## bad status or unsafe octal -> kick (any status residue on the
            ## now-dead client is not an asserted observable).
            self.kicked = True


def _drive(header: str, events: list[str]):
    """Drive the REAL server-side client; return (client, was_kicked)."""
    client = server.SdwdateGuiClient(QLocalSocket())
    client._SdwdateGuiClient__sock_buf = b""
    ## Present a production-faithful socket: feeding bytes directly leaves the
    ## real QLocalSocket Unconnected, which the handshake-timeout guard
    ## (state() != ConnectedState -> return) would read as "already gone". A
    ## real post-header client is Connected. The succeeding write() lets the
    ## Qubes kick path's suppress-reconnect RPC complete cleanly.
    client.client_socket.state = lambda: QLocalSocket.ConnectedState
    client.client_socket.write = lambda data: len(data)
    kicked: list[bool] = []
    client.clientDisconnected.connect(lambda: kicked.append(True))

    def feed(data: bytes) -> None:
        ## Mirror __handle_incoming_data without needing a live socket.
        client._SdwdateGuiClient__sock_buf += data
        if not client.qubes_header_parsed:
            if not client._SdwdateGuiClient__parse_qubes_data():
                return
        client._SdwdateGuiClient__try_parse_commands()

    feed(_HEADER_BYTES[header])
    for event in events:
        if kicked:
            break
        if event == C_TIMEOUT:
            client._SdwdateGuiClient__handshake_timeout()
        else:
            feed(_COMMAND_BYTES[event])
    return client, bool(kicked)


class TestServerProtocolConformance(unittest.TestCase):
    """The real server must match the reference model on every sequence."""

    @settings(max_examples=600, deadline=None)
    @given(
        header=st.sampled_from(HEADERS),
        events=st.lists(st.sampled_from(COMMANDS), max_size=8),
    )
    def test_real_server_matches_reference_model(
        self, header: str, events: list[str]
    ) -> None:
        with mock.patch.object(
            server, "running_in_qubes_os", return_value=True
        ):
            client, real_kicked = _drive(header, events)
        self.addCleanup(client.deleteLater)

        model = _Model(header)
        for event in events:
            model.step(event)

        ctx = f"header={header} events={events}"
        self.assertEqual(
            real_kicked,
            model.kicked,
            f"kick divergence: {ctx} real={real_kicked} model={model.kicked}",
        )
        if not model.kicked:
            self.assertEqual(
                client.client_name_set,
                model.named,
                f"named divergence: {ctx} "
                f"real={client.client_name_set} model={model.named}",
            )
            self.assertEqual(
                client.sdwdate_status.name,
                model.status,
                f"status divergence: {ctx} "
                f"real={client.sdwdate_status.name} model={model.status}",
            )
            self.assertEqual(
                client.sdwdate_msg,
                model.msg,
                f"msg divergence: {ctx} "
                f"real={client.sdwdate_msg!r} model={model.msg!r}",
            )


if __name__ == "__main__":
    unittest.main()
