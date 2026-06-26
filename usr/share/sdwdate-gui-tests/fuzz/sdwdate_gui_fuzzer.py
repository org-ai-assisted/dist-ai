#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Simulator / fuzzer for sdwdate-gui-server, for both the non-Qubes and the
Qubes code paths.

It drives the REAL SdwdateGuiClient / SdwdateTrayIcon classes through a
REAL local-socket connection (so the genuine wire-protocol parser, command
dispatch, kick logic, client list and menu regeneration all run), under the
Qt offscreen platform plugin. No X server, system tray, or qrexec is
needed.

Three drivers:

  * directed  -- a hand-built corpus that exercises every documented branch
                 of the wire protocol and the client state machine, so the
                 code paths are mapped deterministically.
  * protocol  -- random and mutated byte streams fed to the server, plus
                 fragmented framing, to find corner cases in the parser.
  * lifecycle -- random sequences of high-level client operations (connect,
                 name, status, duplicate name, disconnect, reconnect, send
                 garbage, open/close menu) across several concurrent
                 clients, to find races and state-machine bugs.

After every step a set of invariants is checked:

  * no hang        -- a watchdog (SIGALRM) catches an infinite loop in the
                      single-threaded event loop.
  * no crash       -- an unhandled exception in any Qt slot (captured via
                      sys.excepthook) is a defect ("unexpected code
                      execution"), as opposed to the graceful documented
                      kick on bad input.
  * no duplicates  -- no two clients in the client list share a name, and no
                      menu submenu title is duplicated.
  * registration   -- every ready client (named, with a known status) is
                      shown in the menu exactly once.
  * de-registration-- no disconnected client lingers in the client list.
  * valid input    -- a well-formed status message (including one with a
                      newline) must NOT get the client kicked.

With python3-coverage installed, line coverage of
sdwdate_gui_server.py and sdwdate_gui_shared.py is reported, including the
exact lines left unexercised, so coverage gaps are visible.

Exit code 0 if no findings, 1 otherwise. The RNG seed is printed so any
finding is reproducible with --seed.
"""

# pylint: disable=wrong-import-position,no-name-in-module,too-many-lines
# pylint: disable=unused-argument,too-many-branches

import argparse
import os
import random
import signal
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtCore import QEventLoop, QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalServer, QLocalSocket
from PyQt5.QtWidgets import QApplication, QLabel

## The sdwdate_gui_server module is imported lazily in main(), AFTER
## coverage is started, so that its import / class / def lines are counted
## too and the coverage report reflects the genuinely unreached code rather
## than import-time measurement artifacts.
server = None  # pylint: disable=invalid-name  # set by main()


def _import_server():
    """Import and return the sdwdate_gui_server module, or exit 2."""
    try:
        from sdwdate_gui import (  # pylint: disable=import-outside-toplevel
            sdwdate_gui_server,
        )
    except ModuleNotFoundError as exc:
        print(
            "sdwdate-gui is not importable; install the 'sdwdate-gui' "
            "package or set PYTHONPATH to its dist-packages directory",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    return sdwdate_gui_server


_APP = QApplication.instance() or QApplication(["sdwdate-gui-fuzzer"])

## Unhandled exceptions in Qt slots are routed here by PyQt rather than
## propagating out of processEvents(); collect them so a crash or a
## watchdog-interrupted hang becomes an observable finding.
_CAUGHT: list[tuple[str, str]] = []


def _excepthook(exc_type, exc, _tb) -> None:
    _CAUGHT.append((exc_type.__name__, str(exc)))


sys.excepthook = _excepthook


class _Hang(Exception):
    """Raised by the SIGALRM watchdog when the event loop fails to return."""


def _on_alarm(_sig, _frame) -> None:
    raise _Hang()


signal.signal(signal.SIGALRM, _on_alarm)


class FakeListener(QObject):  # pylint: disable=too-few-public-methods
    """Stub for SdwdateGuiListener; the harness runs its own server."""

    newClient = pyqtSignal(object)


def encode_status_msg(text: str) -> bytes:
    """Encode a status message exactly as sdwdate_gui_client does."""
    out = text.replace("\\", "\\134")
    out = out.replace(" ", "\\040")
    out = out.replace("\n", "\\012")
    return out.encode("ascii")


class FuzzClient:
    """A fuzz client: a QLocalSocket plus wire-protocol helpers."""

    def __init__(self, harness: "Harness", name: str | None = None) -> None:
        self.harness = harness
        self.name = name
        self.sock = QLocalSocket()
        self.sock.connectToServer(harness.sock_path)

    def write(self, data: bytes) -> None:
        """Write raw bytes to the server and flush."""
        if self.sock.state() != QLocalSocket.ConnectedState:
            return
        self.sock.write(data)
        self.sock.flush()

    @staticmethod
    def frame(*parts: bytes) -> bytes:
        """Build a length-prefixed command packet from space-joined parts."""
        payload = b" ".join(parts)
        return len(payload).to_bytes(2, "big") + payload

    def send_header_qubes(self, name: str) -> None:
        """Send a qrexec connection header carrying the source VM name."""
        self.write(b"sdwdate-gui.Connect " + name.encode("ascii") + b"\0")

    def send_header_blank(self) -> None:
        """Send the empty qrexec header a non-Qubes client sends."""
        self.write(b"\0")

    def set_name(self, name: str) -> None:
        """Send a set_client_name command (non-Qubes path)."""
        self.write(self.frame(b"set_client_name", name.encode("ascii")))

    def set_status(self, status: str, msg: str) -> None:
        """Send a well-formed set_sdwdate_status command."""
        self.write(
            self.frame(
                b"set_sdwdate_status",
                status.encode("ascii"),
                encode_status_msg(msg),
            )
        )

    def set_tor(self, status: str) -> None:
        """Send a set_tor_status command."""
        self.write(self.frame(b"set_tor_status", status.encode("ascii")))

    def disconnect(self) -> None:
        """Disconnect from the server."""
        self.sock.disconnectFromServer()


class Finding:  # pylint: disable=too-few-public-methods
    """A single fuzzer finding."""

    def __init__(self, mode: str, kind: str, detail: str, repro: str) -> None:
        self.mode = mode
        self.kind = kind
        self.detail = detail
        self.repro = repro

    def __str__(self) -> str:
        return f"[{self.mode}] {self.kind}: {self.detail}  (repro: {self.repro})"


class Harness:
    """A running server + tray with its own local socket, in one OS mode."""

    def __init__(self, qubes: bool) -> None:
        self.qubes = qubes
        self.mode = "qubes" if qubes else "nonqubes"
        server.running_in_qubes_os = lambda: qubes
        server.SdwdateGuiListener = FakeListener

        self.tray = server.SdwdateTrayIcon()
        self._tmpdir = tempfile.mkdtemp(prefix="sdwd-fuzz-")
        self.sock_path = os.path.join(self._tmpdir, "server.sock")
        QLocalServer.removeServer(self.sock_path)
        self.server = QLocalServer()
        if not self.server.listen(self.sock_path):
            raise RuntimeError(
                f"could not listen on {self.sock_path}: " f"{self.server.errorString()}"
            )
        self.server.newConnection.connect(self._accept)
        self.clients: list[FuzzClient] = []

    def _accept(self) -> None:
        sock = self.server.nextPendingConnection()
        if sock is None:
            return
        client = server.SdwdateGuiClient(sock, self.server)
        self.tray.accept_client(client)

    def pump(self, rounds: int = 8, watchdog_s: float = 2.0) -> None:
        """Process pending events, with a watchdog against infinite loops."""
        for _ in range(rounds):
            signal.setitimer(signal.ITIMER_REAL, watchdog_s)
            try:
                _APP.processEvents(QEventLoop.AllEvents, 25)
            except _Hang:
                _CAUGHT.append(("_Hang", "event loop did not return"))
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)

    def new_client(self, name: str | None = None) -> FuzzClient:
        """Create and register a fuzz client (not yet named on the server)."""
        client = FuzzClient(self, name)
        self.clients.append(client)
        self.pump()
        return client

    def register(self, client: FuzzClient, name: str) -> None:
        """Make a client known to the server using the mode's name path."""
        if self.qubes:
            client.send_header_qubes(name)
        else:
            client.send_header_blank()
            client.set_name(name)
        client.name = name
        self.pump()

    def ready_clients(self) -> list:
        """Server-side clients that regen_menu should display."""
        result = []
        for client in self.tray.client_list:
            if client.client_name is None:
                continue
            if (
                client.tor_status == server.TorStatus.UNKNOWN
                and client.sdwdate_status == server.SdwdateStatus.UNKNOWN
            ):
                continue
            result.append(client)
        return result

    def check_invariants(self, mode: str, repro: str) -> list[Finding]:
        """Force a menu refresh and check every invariant."""
        findings: list[Finding] = []

        for kind, detail in _CAUGHT:
            if kind == "_Hang":
                findings.append(Finding(mode, "HANG", "event loop wedged", repro))
            else:
                findings.append(
                    Finding(
                        mode,
                        "CRASH",
                        f"unhandled {kind} in a slot: {detail}",
                        repro,
                    )
                )
        _CAUGHT.clear()

        ## Refresh the menu so it reflects the current client list.
        try:
            self.tray.regen_menu(force_regen=True)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            findings.append(Finding(mode, "CRASH", f"regen_menu raised {exc!r}", repro))
            return findings

        names = [
            c.client_name for c in self.tray.client_list if c.client_name is not None
        ]
        dups = sorted({n for n in names if names.count(n) > 1})
        if dups:
            findings.append(
                Finding(mode, "DUPLICATE_NAME", f"client_list has {dups}", repro)
            )

        titles = [a.text() for a in self.tray.menu.actions() if a.menu()]
        dup_titles = sorted({t for t in titles if titles.count(t) > 1})
        if dup_titles:
            findings.append(
                Finding(mode, "STUCK_MENU", f"duplicate submenu {dup_titles}", repro)
            )

        ## Registration: the menu shows exactly the ready clients.
        shown = set(id(c) for c in self.tray.menu_client_list)
        ready = set(id(c) for c in self.ready_clients())
        if shown != ready:
            findings.append(
                Finding(
                    mode,
                    "FAILED_REGISTRATION",
                    f"menu shows {len(shown)} clients, " f"{len(ready)} are ready",
                    repro,
                )
            )

        ## De-registration: no client with a dead socket lingers.
        stale = [
            c
            for c in self.tray.client_list
            if c.client_socket.state() == QLocalSocket.UnconnectedState
        ]
        if stale:
            findings.append(
                Finding(
                    mode,
                    "FAILED_DEREGISTRATION",
                    f"{len(stale)} disconnected client(s) still listed",
                    repro,
                )
            )

        return findings

    def teardown(self) -> None:
        """Disconnect clients and close the server."""
        for client in self.clients:
            client.disconnect()
        self.pump()
        if self.tray.msg_window is not None:
            self.tray.msg_window.close()
            self.tray.msg_window.deleteLater()
        self.server.close()
        QLocalServer.removeServer(self.sock_path)
        self.tray.deleteLater()
        self.pump()


VALID_VM_NAMES = ["sys-whonix", "anon-whonix", "disp5711", "disp9001", "work"]
INVALID_NONQUBES_LONG = "x" * 300
STATUSES = ["success", "busy", "error"]
TOR_STATES = ["running", "stopped", "disabled", "disabled_running", "absent"]


def kicked(client: FuzzClient) -> bool:
    """True once the server has disconnected (kicked) the client."""
    return client.sock.state() == QLocalSocket.UnconnectedState


def server_client(harness: Harness, name: str):
    """Return the server-side client object with the given name, if any."""
    for client in harness.tray.client_list:
        if client.client_name == name:
            return client
    return None


## ---------------------------------------------------------------------------
## Directed corpus: one function per scenario, mapping the protocol branches.
## Each returns scenario-specific findings; the runner also checks the generic
## invariants afterwards. 'modes' restricts a case to qubes / nonqubes.
## ---------------------------------------------------------------------------


def _d_valid_lifecycle(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.set_status("success", "all good")
    c.set_tor("running")
    h.pump()
    if kicked(c):
        findings.append(
            Finding(mode, "FAILED_REGISTRATION", "valid client kicked", repro)
        )
    return findings


def _d_status_newline(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.set_status("success", "line one\nline two")
    h.pump()
    if kicked(c):
        findings.append(
            Finding(
                mode,
                "FAILED_REGISTRATION",
                "client kicked by a newline in status",
                repro,
            )
        )
    sc = server_client(h, "disp5711")
    if sc is not None and sc.sdwdate_msg is not None and "\n" not in sc.sdwdate_msg:
        findings.append(
            Finding(mode, "CRASH", f"newline not decoded: {sc.sdwdate_msg!r}", repro)
        )
    return findings


def _d_status_all_escapes(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.set_status("error", "a b\\c\nd ~")
    h.pump()
    if kicked(c):
        findings.append(
            Finding(
                mode, "FAILED_REGISTRATION", "client kicked by valid escapes", repro
            )
        )
    return findings


def _d_status_unsafe_octal(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    ## Raw frame embedding a NUL escape (\000), which must be rejected.
    c.write(FuzzClient.frame(b"set_sdwdate_status", b"success", b"x\\000y"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "unsafe octal escape not rejected", repro)
        )
    return findings


def _d_status_before_name(h, mode, repro):
    findings = []
    c = h.new_client()
    c.send_header_blank()
    c.set_status("success", "premature")
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "status accepted before name was set", repro)
        )
    return findings


def _d_name_change(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "first")
    c.set_name("second")
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "name change after set was not rejected", repro)
        )
    return findings


def _d_duplicate_name(h, mode, repro):
    findings = []
    c1 = h.new_client()
    h.register(c1, "dup")
    c1.set_status("success", "one")
    c2 = h.new_client()
    h.register(c2, "dup")
    c2.set_status("success", "two")
    h.pump()
    names = [x.client_name for x in h.tray.client_list if x.client_name == "dup"]
    if len(names) != 1:
        findings.append(
            Finding(mode, "DUPLICATE_NAME", f"{len(names)} 'dup' clients remain", repro)
        )
    if mode == "qubes":
        ## Qubes: the newest connection wins, the stale one is kicked.
        if not kicked(c1):
            findings.append(
                Finding(
                    mode,
                    "DUPLICATE_NAME",
                    "stale duplicate not dropped on qubes",
                    repro,
                )
            )
    else:
        ## non-Qubes: the newcomer is kicked, the established client stays.
        if not kicked(c2):
            findings.append(
                Finding(mode, "DUPLICATE_NAME", "duplicate newcomer not kicked", repro)
            )
    return findings


def _d_fragmented_message(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    frame = FuzzClient.frame(b"set_sdwdate_status", b"success", b"hello")
    ## Deliver the frame in two pieces, pumping in between, as a socket may.
    c.write(frame[:3])
    h.pump()
    c.write(frame[3:])
    h.pump()
    if kicked(c):
        findings.append(
            Finding(
                mode,
                "FAILED_REGISTRATION",
                "client kicked by a fragmented message",
                repro,
            )
        )
    return findings


def _d_length_too_long(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.write(b"\xff\xff" + b"x" * 10)  # claims 65535 bytes
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "over-long length prefix not rejected", repro)
        )
    return findings


def _d_nonprintable_command(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.write(FuzzClient.frame(b"set_tor_status", b"run\x01ning"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "non-printable command bytes not rejected", repro)
        )
    return findings


def _d_zero_length_then_valid(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.write(b"\x00\x00")  # zero-length message, must be skipped
    c.set_status("busy", "ok")
    h.pump()
    if kicked(c):
        findings.append(
            Finding(mode, "CRASH", "zero-length message broke the stream", repro)
        )
    return findings


def _d_unknown_command(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    ## An unknown command is a protocol violation and must be rejected.
    c.write(FuzzClient.frame(b"definitely_not_a_command", b"arg"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "PROTOCOL", "unknown command not rejected", repro)
        )
    return findings


def _d_batched_commands(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    batch = FuzzClient.frame(
        b"set_sdwdate_status", b"success", b"ok"
    ) + FuzzClient.frame(b"set_tor_status", b"running")
    c.write(batch)
    h.pump()
    if kicked(c):
        findings.append(
            Finding(mode, "CRASH", "batched commands kicked the client", repro)
        )
    return findings


def _d_tor_invalid(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.write(FuzzClient.frame(b"set_tor_status", b"bogus"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "invalid tor status not rejected", repro)
        )
    return findings


def _d_wrong_arg_count(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "disp5711")
    c.write(FuzzClient.frame(b"set_client_name"))  # zero args
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "wrong argument count not rejected", repro)
        )
    return findings


def _d_qubes_header_overlong(h, mode, repro):
    findings = []
    c = h.new_client()
    c.write(b"x" * 5000)  # no NUL, exceeds the qrexec header cap
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "over-long qrexec header not rejected", repro)
        )
    return findings


def _d_qubes_header_nonprintable(h, mode, repro):
    findings = []
    c = h.new_client()
    c.write(b"sdwdate-gui.Connect dis\x01p\0")
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "non-printable qrexec header not rejected", repro)
        )
    return findings


def _d_deregister(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "gone")
    c.set_status("success", "bye")
    h.pump()
    c.disconnect()
    h.pump()
    if server_client(h, "gone") is not None:
        findings.append(
            Finding(
                mode, "FAILED_DEREGISTRATION", "disconnected client still listed", repro
            )
        )
    return findings


def _d_reconnect(h, mode, repro):
    findings = []
    c1 = h.new_client()
    h.register(c1, "again")
    c1.set_status("success", "v1")
    h.pump()
    c1.disconnect()
    h.pump()
    c2 = h.new_client()
    h.register(c2, "again")
    c2.set_status("success", "v2")
    h.pump()
    names = [x.client_name for x in h.tray.client_list if x.client_name == "again"]
    if len(names) != 1:
        findings.append(
            Finding(
                mode, "DUPLICATE_NAME", f"reconnect left {len(names)} clients", repro
            )
        )
    return findings


def _d_qubes_nameless_header_then_name(h, mode, repro):
    findings = []
    ## A qrexec header with no source-VM part leaves the name unset, so a
    ## following set_client_name is validated by the Qubes name rules.
    c = h.new_client()
    c.write(b"sdwdate-gui.Connect\0")  # header, no name part
    c.set_name("legit-vm")
    c.set_status("success", "ok")
    h.pump()
    if kicked(c):
        findings.append(
            Finding(
                mode,
                "FAILED_REGISTRATION",
                "valid Qubes name via set_client_name kicked",
                repro,
            )
        )
    return findings


def _d_qubes_nameless_header_bad_name(h, mode, repro):
    findings = []
    for bad in ["bad name", "Domain-0", "x-dm", "9starts-digit", "a" * 40]:
        c = h.new_client()
        c.write(b"sdwdate-gui.Connect\0")
        c.set_name(bad)
        h.pump()
        if not kicked(c):
            findings.append(
                Finding(
                    mode, "CRASH", f"invalid Qubes name {bad!r} not rejected", repro
                )
            )
    return findings


def _d_nonqubes_name_too_long(h, mode, repro):
    findings = []
    c = h.new_client()
    c.send_header_blank()
    c.set_name("x" * 300)  # exceeds the 255-char non-Qubes limit
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "over-long non-Qubes name not rejected", repro)
        )
    return findings


def _d_status_roundtrip(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "rtvm")
    ## Including sequences whose decode could re-form another escape, which
    ## an order-dependent decoder would mangle.
    for text in [
        "plain message",
        "a b c",
        "back\\slash",
        "line1\nline2",
        "\n\\012",
        "x\\134\\012y",
        "trailing \\040",
    ]:
        c.set_status("success", text)
        h.pump()
        sc = server_client(h, "rtvm")
        if sc is not None and not kicked(c) and sc.sdwdate_msg != text:
            findings.append(
                Finding(
                    mode,
                    "DECODE_MISMATCH",
                    f"status decode wrong: in={text!r} out={sc.sdwdate_msg!r}",
                    repro,
                )
            )
    return findings


def _d_status_markup_escaped(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "mkvm")
    ## A client is a separate, less-trusted VM; its status message must not
    ## be able to inject markup into the rich-text status window.
    c.set_status("success", "<marker7>inject</marker7>")
    h.pump()
    h.tray.regen_menu(force_regen=True)
    trigger_safe_actions(h, {"Show sdwdate status"})
    h.pump()
    window = h.tray.msg_window
    if window is not None:
        rendered = " ".join(label.text() for label in window.findChildren(QLabel))
        if "<marker7>" in rendered:
            findings.append(
                Finding(
                    mode,
                    "INJECTION",
                    "unescaped client markup rendered in the status window",
                    repro,
                )
            )
    return findings


def _d_status_display_truncated(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "longvm")
    ## A message that fits the wire frame but exceeds the display cap.
    big = "X" * 3000
    c.set_status("success", big)
    h.pump()
    if kicked(c):
        return findings  # rejected at the wire; truncation not exercised
    h.tray.regen_menu(force_regen=True)
    trigger_safe_actions(h, {"Show sdwdate status"})
    h.pump()
    window = h.tray.msg_window
    if window is not None:
        rendered = " ".join(label.text() for label in window.findChildren(QLabel))
        shown = rendered.count("X")
        if shown >= len(big):
            findings.append(
                Finding(
                    mode,
                    "UNBOUNDED_STRING",
                    f"status message not truncated for display ({shown} shown)",
                    repro,
                )
            )
    return findings


def _d_connection_cap(h, mode, repro):
    findings = []
    ## Open far more connections than any reasonable limit; a bounded server
    ## must reject the surplus rather than accept them all.
    attempts = 100
    for _ in range(attempts):
        h.new_client()  # connect without ever sending a name
    h.pump()
    if len(h.tray.client_list) >= attempts:
        findings.append(
            Finding(
                mode,
                "UNBOUNDED_CONNECTIONS",
                f"all {attempts} connections accepted; no limit enforced",
                repro,
            )
        )
    return findings


def _d_qubes_header_name_too_long(h, mode, repro):
    findings = []
    c = h.new_client()
    ## A qrexec header carrying an over-long source-VM name must be rejected.
    c.write(b"sdwdate-gui.Connect " + b"a" * 40 + b"\0")
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(
                mode, "UNBOUNDED_STRING", "over-long qrexec header name accepted", repro
            )
        )
    return findings


def _d_tor_before_name(h, mode, repro):
    findings = []
    c = h.new_client()
    if h.qubes:
        c.write(b"sdwdate-gui.Connect\0")  # nameless header -> name unset
    else:
        c.send_header_blank()
    c.set_tor("running")  # tor status before a name -> kick
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "tor status before name not rejected", repro)
        )
    return findings


def _d_invalid_octal(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "octvm")
    ## \999 matches the escape regex but is not a valid octal number.
    c.write(FuzzClient.frame(b"set_sdwdate_status", b"success", b"a\\999b"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "invalid octal escape not rejected", repro)
        )
    return findings


def _d_invalid_status(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "stvm")
    c.write(FuzzClient.frame(b"set_sdwdate_status", b"notastatus", b"m"))
    h.pump()
    if not kicked(c):
        findings.append(
            Finding(mode, "CRASH", "invalid sdwdate status not rejected", repro)
        )
    return findings


def _d_deferred_regen(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "defvm")
    c.set_status("success", "m1")
    h.pump()
    h.tray.menu.show()  # menu visible -> a regen must be deferred
    c.set_status("busy", "m2")
    h.pump()
    ## Simulate the popup re-opening, which flushes the deferred regen.
    h.tray.handle_menu_show()
    h.tray.menu.hide()
    h.pump()
    return findings


def _d_show_menu_paths(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "menuvm")
    c.set_status("success", "m")
    h.pump()
    ## The tray-activation handler (left- and right-click).
    h.tray.show_menu(server.QSystemTrayIcon.ActivationReason.Trigger)
    h.tray.show_menu(server.QSystemTrayIcon.ActivationReason.Context)
    h.tray.menu.hide()
    h.pump()
    return findings


def _d_disconnected_message(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "deadvm")
    c.set_tor("running")
    c.set_status("success", "m")
    h.pump()
    sc = server_client(h, "deadvm")
    if sc is not None:
        ## abort() drops the socket to Unconnected immediately, so the
        ## status / action handlers take their disconnected-client path.
        sc.client_socket.abort()
        h.tray.show_status_msg(server.MessageType.SDWDATE, sc)
        h.tray.show_status_msg(server.MessageType.TOR, sc)
        h.tray.run_client_method(sc, sc.open_sdwdate_log)
    h.pump()
    return findings


def iter_menu_actions(menu):
    """Yield every action in a menu, recursing into submenus."""
    for action in menu.actions():
        submenu = action.menu()
        if submenu is not None:
            yield from iter_menu_actions(submenu)
        else:
            yield action


def trigger_safe_actions(h, wanted=None) -> None:
    """
    Trigger menu actions to exercise the GUI handlers. The '&Exit' action is
    never triggered (it calls sys.exit). If 'wanted' is given, only actions
    whose label matches are triggered.
    """
    for action in list(iter_menu_actions(h.tray.menu)):
        label = action.text().replace("&", "")
        if label == "Exit" or not action.isEnabled():
            continue
        if wanted is not None and label not in wanted:
            continue
        action.trigger()


def _d_menu_actions(h, mode, repro):
    findings = []
    c = h.new_client()
    h.register(c, "torvm")
    ## Cycle Tor states and open the Tor status window for each, covering
    ## every branch of the Tor status message.
    for tor in ["running", "stopped", "disabled", "disabled_running"]:
        c.set_tor(tor)
        h.pump()
        h.tray.regen_menu(force_regen=True)
        trigger_safe_actions(h, {"Show Tor status"})
        h.pump()
    c.set_status("success", "a status message")
    h.pump()
    h.tray.regen_menu(force_regen=True)
    ## Open the sdwdate status window and invoke each server-to-client RPC.
    trigger_safe_actions(
        h,
        {
            "Show sdwdate status",
            "Tor control panel",
            "Open sdwdate's log",
            "Restart sdwdate",
            "Stop sdwdate",
        },
    )
    h.pump()
    ## Close the status window via its Close button handler.
    if h.tray.msg_window is not None:
        h.tray.msg_window.quiet_close()
    return findings


BOTH = ("qubes", "nonqubes")
DIRECTED = [
    ("menu_actions", BOTH, _d_menu_actions),
    ("qubes_nameless_header_then_name", ("qubes",), _d_qubes_nameless_header_then_name),
    ("qubes_nameless_header_bad_name", ("qubes",), _d_qubes_nameless_header_bad_name),
    ("nonqubes_name_too_long", ("nonqubes",), _d_nonqubes_name_too_long),
    ("status_roundtrip", BOTH, _d_status_roundtrip),
    ("status_markup_escaped", BOTH, _d_status_markup_escaped),
    ("status_display_truncated", BOTH, _d_status_display_truncated),
    ("connection_cap", BOTH, _d_connection_cap),
    ("qubes_header_name_too_long", ("qubes",), _d_qubes_header_name_too_long),
    ("tor_before_name", BOTH, _d_tor_before_name),
    ("invalid_octal", BOTH, _d_invalid_octal),
    ("invalid_status", BOTH, _d_invalid_status),
    ("deferred_regen", BOTH, _d_deferred_regen),
    ("show_menu_paths", BOTH, _d_show_menu_paths),
    ("disconnected_message", BOTH, _d_disconnected_message),
    ("valid_lifecycle", BOTH, _d_valid_lifecycle),
    ("status_newline", BOTH, _d_status_newline),
    ("status_all_escapes", BOTH, _d_status_all_escapes),
    ("status_unsafe_octal", BOTH, _d_status_unsafe_octal),
    ("status_before_name", ("nonqubes",), _d_status_before_name),
    ("name_change", ("nonqubes",), _d_name_change),
    ("duplicate_name", BOTH, _d_duplicate_name),
    ("fragmented_message", BOTH, _d_fragmented_message),
    ("length_too_long", BOTH, _d_length_too_long),
    ("nonprintable_command", BOTH, _d_nonprintable_command),
    ("zero_length_then_valid", BOTH, _d_zero_length_then_valid),
    ("unknown_command", BOTH, _d_unknown_command),
    ("batched_commands", BOTH, _d_batched_commands),
    ("tor_invalid", BOTH, _d_tor_invalid),
    ("wrong_arg_count", BOTH, _d_wrong_arg_count),
    ("qubes_header_overlong", ("qubes",), _d_qubes_header_overlong),
    ("qubes_header_nonprintable", ("qubes",), _d_qubes_header_nonprintable),
    ("deregister", BOTH, _d_deregister),
    ("reconnect", BOTH, _d_reconnect),
]


def run_directed(modes) -> list[Finding]:
    """Run the directed corpus for the requested modes."""
    findings: list[Finding] = []
    for name, case_modes, fn in DIRECTED:
        for mode in modes:
            if mode not in case_modes:
                continue
            harness = Harness(qubes=mode == "qubes")
            repro = f"directed:{name}"
            _CAUGHT.clear()
            try:
                findings += fn(harness, mode, repro)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                findings.append(
                    Finding(mode, "CRASH", f"directed {name} raised {exc!r}", repro)
                )
            findings += harness.check_invariants(mode, repro)
            harness.teardown()
    return findings


## ---------------------------------------------------------------------------
## Random protocol fuzzing: arbitrary / mutated byte streams to the server.
## ---------------------------------------------------------------------------


def _rand_bytes(rng, lo=1, hi=120) -> bytes:
    return bytes(rng.randrange(256) for _ in range(rng.randint(lo, hi)))


def _rand_text(rng) -> str:
    pool = "abc 123 \\\n~/.-_"
    return "".join(rng.choice(pool) for _ in range(rng.randint(0, 24)))


def _send_random_payload(h, rng, client) -> None:
    """Send one randomly chosen malformed or valid payload to a client."""
    choice = rng.randint(0, 6)
    if choice == 0:
        client.write(_rand_bytes(rng))
    elif choice == 1:
        cmd = rng.choice(
            [b"set_client_name", b"set_sdwdate_status", b"set_tor_status", b"bogus"]
        )
        args = [
            _rand_text(rng).encode("ascii", "replace") for _ in range(rng.randint(0, 3))
        ]
        client.write(FuzzClient.frame(cmd, *args))
    elif choice == 2:
        ## Declared length larger than the body: an incomplete message.
        body = _rand_bytes(rng, 1, 20)
        client.write((len(body) + rng.randint(1, 50)).to_bytes(2, "big") + body)
    elif choice == 3:
        ## Fragmented valid status frame.
        frame = FuzzClient.frame(
            b"set_sdwdate_status", b"success", encode_status_msg(_rand_text(rng))
        )
        cut = rng.randint(1, max(1, len(frame) - 1))
        client.write(frame[:cut])
        h.pump()
        client.write(frame[cut:])
    elif choice == 4:
        ## Over-long declared length (> 4096).
        client.write(
            (4097 + rng.randint(0, 60000)).to_bytes(2, "big") + _rand_bytes(rng)
        )
    elif choice == 5:
        client.set_status(rng.choice(STATUSES + ["bogus"]), _rand_text(rng))
    else:
        client.set_tor(rng.choice(TOR_STATES + ["bogus"]))


def run_protocol(mode, rng, iterations) -> list[Finding]:
    """Feed random / mutated byte streams to a server in one mode."""
    findings: list[Finding] = []
    harness = Harness(qubes=mode == "qubes")
    counter = 0
    for i in range(iterations):
        ## Keep a small pool of registered clients alive.
        alive = [c for c in harness.clients if not kicked(c)]
        if len(alive) < 3:
            counter += 1
            c = harness.new_client()
            harness.register(c, f"vm{counter}")
            c.set_status("success", "init")
            harness.pump()
            alive.append(c)
        target = rng.choice(alive)
        _CAUGHT.clear()
        _send_random_payload(harness, rng, target)
        harness.pump()
        findings += harness.check_invariants(
            mode, f"seed-based protocol mode={mode} iter={i}"
        )
        if findings and len(findings) > 40:
            break
    harness.teardown()
    return findings


## ---------------------------------------------------------------------------
## Lifecycle fuzzing: random sequences of high-level client operations.
## ---------------------------------------------------------------------------


def run_lifecycle(mode, rng, iterations) -> list[Finding]:
    """Drive random connect/name/status/disconnect/reconnect sequences."""
    findings: list[Finding] = []
    harness = Harness(qubes=mode == "qubes")
    name_pool = list(VALID_VM_NAMES)
    counter = 0

    for i in range(iterations):
        alive = [c for c in harness.clients if not kicked(c)]
        op = rng.randint(0, 10)
        _CAUGHT.clear()

        if op in (0, 1) or not alive:
            ## Connect + register, sometimes with a duplicate name.
            counter += 1
            name = rng.choice(name_pool) if rng.random() < 0.4 else f"disp{counter}"
            c = harness.new_client()
            harness.register(c, name)
            c.set_status(rng.choice(STATUSES), _rand_text(rng))
        elif op == 2:
            c = rng.choice(alive)
            c.set_status(rng.choice(STATUSES), _rand_text(rng))
        elif op == 3:
            rng.choice(alive).set_tor(rng.choice(TOR_STATES))
        elif op == 4:
            rng.choice(alive).disconnect()
        elif op == 5:
            ## Reconnect a fresh client with an existing name.
            existing = [
                c.client_name for c in harness.tray.client_list if c.client_name
            ]
            if existing:
                c = harness.new_client()
                harness.register(c, rng.choice(existing))
                c.set_status(rng.choice(STATUSES), "re")
        elif op == 6:
            rng.choice(alive).write(_rand_bytes(rng))
        elif op == 7:
            harness.tray.menu.show()  # open menu -> exercise regen deferral
        elif op == 8:
            harness.tray.menu.hide()
        elif op == 9:
            ## Exercise the menu action handlers (status windows, RPCs).
            harness.tray.regen_menu(force_regen=True)
            trigger_safe_actions(harness)
        else:
            ## Trigger an action, then immediately drop a client, to reach
            ## the disconnected-client path in run_client_method.
            harness.tray.regen_menu(force_regen=True)
            if alive:
                rng.choice(alive).disconnect()
            trigger_safe_actions(harness)

        harness.pump()
        findings += harness.check_invariants(
            mode, f"seed-based lifecycle mode={mode} iter={i}"
        )
        if len(findings) > 40:
            break

    harness.teardown()
    return findings


## ---------------------------------------------------------------------------
## Coverage + entry point.
## ---------------------------------------------------------------------------


def _source_files() -> list[str]:
    files = [server.__file__]
    shared = sys.modules.get("sdwdate_gui.sdwdate_gui_shared")
    if shared is not None and shared.__file__:
        files.append(shared.__file__)
    return files


def _report_coverage(cov) -> None:
    print("\n=== code-path coverage (sdwdate_gui_server / _shared) ===")
    for path in _source_files():
        try:
            _fn, statements, _excl, missing, _fmt = cov.analysis2(path)
        except Exception:  # pylint: disable=broad-exception-caught
            continue
        total = len(statements)
        covered = total - len(missing)
        pct = 100.0 * covered / total if total else 100.0
        name = os.path.basename(path)
        print(f"  {name}: {covered}/{total} lines ({pct:.1f}%)")
        if missing:
            print(f"    unexercised lines: {missing}")


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="sdwdate-gui server fuzzer")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--iterations", type=int, default=400)
    parser.add_argument("--mode", choices=["both", "qubes", "nonqubes"], default="both")
    parser.add_argument("--no-coverage", action="store_true")
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    print(
        f"sdwdate-gui fuzzer: seed={seed} iterations={args.iterations} mode={args.mode}"
    )

    modes = ["qubes", "nonqubes"] if args.mode == "both" else [args.mode]

    cov = None
    if not args.no_coverage:
        try:
            import coverage  # pylint: disable=import-outside-toplevel

            cov = coverage.Coverage(
                include=[
                    f"*{os.sep}sdwdate_gui_server.py",
                    f"*{os.sep}sdwdate_gui_shared.py",
                ]
            )
            cov.start()
        except ImportError:
            print("(python3-coverage not installed; skipping coverage report)")

    ## Import the module under test only now, so coverage (started above)
    ## also accounts for its import / class / def lines.
    global server  # pylint: disable=global-statement
    server = _import_server()

    findings: list[Finding] = []
    findings += run_directed(modes)
    for mode in modes:
        findings += run_protocol(
            mode, random.Random(seed ^ 0x9E3779B1 ^ hash(mode)), args.iterations
        )
        findings += run_lifecycle(
            mode, random.Random(seed ^ 0x51ED270B ^ hash(mode)), args.iterations
        )

    if cov is not None:
        cov.stop()
        _report_coverage(cov)

    print("\n=== findings ===")
    if not findings:
        print("none")
        return 0

    by_kind: dict[str, int] = {}
    seen: set[str] = set()
    for finding in findings:
        by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
        key = f"{finding.mode}:{finding.kind}:{finding.detail}"
        if key not in seen:
            seen.add(key)
            print(f"  {finding}")
    print(
        "\nsummary by kind: "
        + ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items()))
    )
    print(f"total findings: {len(findings)} ({len(seen)} unique)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
