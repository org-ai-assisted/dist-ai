#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Minimal QMP (QEMU Machine Protocol) client -- the parse target for qmp_fuzz.py.

QMP is QEMU's line-delimited-JSON control socket. This hand-rolled client (stdlib
socket + json, no extra package) exists so the boot harness can do what the serial
console cannot do reliably: a graceful ACPI shutdown (system_powerdown) and telling
a guest REBOOT from a POWEROFF via the SHUTDOWN event 'reason' ('guest-reset' vs
'guest-shutdown'). Its line parser is pure and side-effect free so it can be fuzzed
directly (qmp_fuzz.py), which surfaced real hardening cases (malformed JSON,
non-object messages, deeply nested payloads, unbounded lines).
"""

import json
import socket
import time


class QMPError(RuntimeError):
    """A QMP message was malformed or the QMP exchange failed. Kept distinct from a raw
    JSONDecodeError so callers can treat a hostile/garbled stream as a clean protocol failure
    rather than an unexpected crash."""


## A QMP message is small (a command or an event). Cap the line read so a hostile or wedged
## peer that never sends a newline cannot make readline() consume unbounded memory.
_MAX_QMP_LINE = 1 << 20


class QMPClient:
    """
    Minimal QMP (QEMU Machine Protocol) client -- line-delimited JSON over a unix socket.

    QMP is the VM-level control channel; it complements (does not replace) the serial console.
    The serial console logs in and runs guest commands; QMP does what serial cannot do reliably:
    a graceful ACPI shutdown (system_powerdown) and telling a guest REBOOT from a POWEROFF via
    the SHUTDOWN event's 'reason' ('guest-reset' vs 'guest-shutdown') instead of guessing from a
    serial EOF. Hand-rolled on stdlib socket+json so the harness needs no extra package.
    """

    def __init__(self, sock_path):
        self.sock_path = sock_path
        self._sock = None
        self._rfile = None
        self.last_shutdown_reason = None

    def connect(self, timeout=60):
        """Connect once qemu has created the socket (it is created at qemu start, so retry),
        read the QMP greeting, and negotiate capabilities. Returns True on success."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._sock.connect(self.sock_path)
                break
            except (FileNotFoundError, ConnectionRefusedError, OSError):
                if self._sock is not None:
                    self._sock.close()
                    self._sock = None
                time.sleep(0.25)
        if self._sock is None:
            return False
        self._sock.settimeout(timeout)
        self._rfile = self._sock.makefile("r", encoding="utf-8")
        ## Greeting: {"QMP": {...}}. Then enter command mode. A malformed greeting (QMPError)
        ## means this is not a QMP peer -- fail cleanly rather than crash.
        try:
            greeting = self._read_message()
        except QMPError:
            self.close()
            return False
        if not greeting or "QMP" not in greeting:
            self.close()
            return False
        resp = self.execute("qmp_capabilities")
        if resp is None or "error" in resp:
            ## Close on failure too (not just the greeting paths) so a failed negotiation does
            ## not leak the socket + makefile fds.
            self.close()
            return False
        return True

    @staticmethod
    def _parse_line(line):
        """
        Parse one QMP line into a dict. Pure and side-effect free (so it can be fuzzed
        directly). Raises QMPError -- never a bare JSONDecodeError/RecursionError -- on anything
        malformed: non-JSON, valid JSON that is not an object, or JSON too deeply nested to
        parse. An empty/whitespace line yields {} (QMP may send blank keep-alive lines).
        """
        line = line.strip()
        if not line:
            return {}
        try:
            message = json.loads(line)
        except (ValueError, RecursionError) as exc:
            ## ValueError is the base of json.JSONDecodeError; RecursionError guards against a
            ## deeply nested adversarial payload blowing the parser's stack.
            raise QMPError("malformed QMP JSON (%d bytes)" % len(line)) from exc
        if not isinstance(message, dict):
            raise QMPError("QMP message is not a JSON object: %s" % type(message).__name__)
        return message

    def _read_message(self):
        """Read and parse one QMP line. Returns the dict, {} for a blank line, or None on EOF.
        Raises QMPError on a malformed line (callers turn that into a clean failure)."""
        line = self._rfile.readline(_MAX_QMP_LINE)
        if not line:
            return None
        return self._parse_line(line)

    def execute(self, command, arguments=None, timeout=30):
        """
        Send a command and return its response dict ({'return': ...} or {'error': ...}), or None
        on any failure (socket closed/timeout/garbled stream, or no response within `timeout`).

        Robust against a hostile or wedged peer:
        - bounded by an overall deadline, so an ENDLESS event/keep-alive stream cannot spin the
          loop forever;
        - only a real response (a message carrying 'return' or 'error') is returned; asynchronous
          events are recorded and skipped, and blank keep-alive messages ({}) are skipped too, so
          a blank line can never be misattributed as this command's reply;
        - a send/read failure (BrokenPipeError, timeout, OSError) becomes a clean None, never an
          exception escaping into the caller (which would orphan the qemu process).
        """
        if self._sock is None:
            return None
        msg = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        deadline = time.monotonic() + timeout
        try:
            self._sock.sendall((json.dumps(msg) + "\r\n").encode("utf-8"))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                ## Bound each read by the remaining deadline (a byte-trickle within a single
                ## sub-1MiB line is the only residual, capped by _MAX_QMP_LINE).
                self._sock.settimeout(remaining)
                try:
                    reply = self._read_message()
                except QMPError:
                    return None
                if reply is None:
                    return None
                if "event" in reply:
                    self._record_event(reply)
                    continue
                if "return" in reply or "error" in reply:
                    return reply
                ## Anything else (a blank {} keep-alive or an unexpected message) is not this
                ## command's response -- keep reading rather than returning it.
        except (socket.timeout, TimeoutError, OSError):
            return None

    def wait_for_shutdown(self, timeout=300):
        """Block until a SHUTDOWN event (or EOF). Returns the reason string
        ('guest-reset' for a reboot, 'guest-shutdown' for an ACPI poweroff), or None. Bounded by
        an overall deadline (each read is capped by the remaining time) so a silent or trickling
        peer cannot block past `timeout`."""
        if self._sock is None:
            return None
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(remaining)
            try:
                event = self._read_message()
            except (socket.timeout, TimeoutError, OSError):
                return None
            except QMPError:
                ## A garbled line mid-stream: stop waiting rather than loop or crash.
                return None
            if event is None:
                return self.last_shutdown_reason
            if "event" in event:
                self._record_event(event)
                if event.get("event") == "SHUTDOWN":
                    return self.last_shutdown_reason

    def _record_event(self, event):
        if event.get("event") == "SHUTDOWN":
            ## 'data' is normally an object with a 'reason'; a hostile/garbled event may make it
            ## a string/number/missing -- guard so recording never raises.
            data = event.get("data")
            self.last_shutdown_reason = data.get("reason") if isinstance(data, dict) else None

    def close(self):
        if self._rfile is not None:
            try:
                self._rfile.close()
            except OSError:
                pass  ## already-closed / broken fd: nothing more to do on teardown
            self._rfile = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass  ## already-closed / broken fd: nothing more to do on teardown
            self._sock = None
