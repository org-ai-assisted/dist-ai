#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Drive a built derivative-maker ISO headless over the serial console.

The boot command (qemu binary + argv, including the kernel/initrd extraction and
the --entry cmdline selection) is produced by derivative-maker's
``help-steps/dm-qemu --emit-argv``, so this module never duplicates that fragile
xorriso logic -- it asks dm-qemu for the exact argv, spawns it under pexpect, and
drives the serial console: wait for the getty login prompt, log in, run commands
and capture their output + exit status, then power off or reboot.

dm-qemu runs qemu with ``-nographic``, which multiplexes the serial console onto
qemu's stdio, so ``pexpect.spawn(argv)`` owns the serial line directly -- no extra
``-serial`` wiring is needed.

Locating dm-qemu:
  * pass ``dm_qemu=/path/to/help-steps/dm-qemu`` explicitly, OR
  * set ``DERIVATIVE_MAKER_DIR`` (uses ``$DERIVATIVE_MAKER_DIR/help-steps/dm-qemu``), OR
  * fall back to ``~/derivative-maker/help-steps/dm-qemu``.

Reliability of command output: after login the driver runs each command followed
by a unique sentinel line ``<MARK>=$?`` and reads everything up to that marker, so
capture and exit-status detection do not depend on guessing the shell prompt.
"""

import json
import os
import re
import shlex
import socket
import subprocess
import tempfile
import time

import pexpect


class SerialBootError(RuntimeError):
    """A step of the serial boot / login / command sequence failed."""


class QMPError(RuntimeError):
    """A QMP message was malformed or the QMP exchange failed. Kept distinct from a raw
    JSONDecodeError so callers can treat a hostile/garbled stream as a clean protocol failure
    rather than an unexpected crash."""


## A QMP message is small (a command or an event). Cap the line read so a hostile or wedged
## peer that never sends a newline cannot make readline() consume unbounded memory.
_MAX_QMP_LINE = 1 << 20


## A distinctive, shell-safe sentinel. Emitted by the guest shell after each
## command so the driver can bound the command's output and read its exit code
## without parsing an unknown prompt string.
_MARK = "__DM_ISO_BOOT_MARK__"


## Each boot-role session accepts ONLY its own dedicated account: the sysmaint
## session logs in as 'sysmaint', the user session as 'user'. Any other pairing
## (e.g. 'user' in the sysmaint session) is rejected by the image, so there is no
## default account for other entries -- the caller must pass username= explicitly.
_ENTRY_ACCOUNT = {
    "user": "user",
    "sysmaint": "sysmaint",
}


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


def _default_dm_qemu():
    env_dir = os.environ.get("DERIVATIVE_MAKER_DIR", "").strip()
    if env_dir:
        return os.path.join(env_dir, "help-steps", "dm-qemu")
    return os.path.expanduser("~/derivative-maker/help-steps/dm-qemu")


class SerialBootSession:
    """
    One qemu boot of an ISO, driven over the serial console.

    Use as a context manager so qemu is always reaped and the dm-qemu
    kernel/initrd workdir is always removed, even on failure:

        with SerialBootSession(iso, entry="sysmaint") as sess:
            sess.wait_for_login()
            sess.login()
            out, rc = sess.run("systemcheck --leak-tests --verbose", timeout=1800)
            sess.poweroff()
    """

    def __init__(
        self,
        iso,
        entry="user",
        dm_qemu=None,
        username=None,
        password="changeme",
        arch=None,
        fast=False,
        memory=None,
        smp=None,
        extra_append=None,
        logfile=None,
        use_qmp=True,
    ):
        self.iso = iso
        self.entry = entry
        self.dm_qemu = dm_qemu or _default_dm_qemu()
        ## The account is fixed by the boot-role session unless overridden: sysmaint
        ## -> 'sysmaint', user -> 'user'. Other entries have no valid account.
        if username is None:
            username = _ENTRY_ACCOUNT.get(entry)
            if username is None:
                raise SerialBootError(
                    "no dedicated login account for entry '%s'; pass username= "
                    "explicitly (valid sessions: %s)"
                    % (entry, ", ".join(sorted(_ENTRY_ACCOUNT)))
                )
        self.username = username
        self.password = password
        self.arch = arch
        self.fast = fast
        self.memory = memory
        self.smp = smp
        self.extra_append = extra_append
        ## Where the raw serial transcript is mirrored (a file object, e.g.
        ## sys.stdout.buffer, or None). pexpect writes bytes, so callers pass a
        ## binary stream or leave it None.
        self.logfile = logfile
        self.use_qmp = use_qmp
        self.child = None
        self._workdir = None
        ## QMP control channel (set up in __enter__ when use_qmp): a unix socket qemu serves
        ## and this driver connects to for graceful shutdown + reboot/poweroff detection.
        self.qmp = None
        self._qmp_dir = None
        self._qmp_sock = None

    ## ----- lifecycle -----------------------------------------------------

    def _emit_argv(self):
        """Ask dm-qemu for the qemu argv and (in --verbose) its workdir."""
        if not os.access(self.dm_qemu, os.X_OK):
            raise SerialBootError(
                "dm-qemu not found or not executable: %s "
                "(pass dm_qemu=... or set DERIVATIVE_MAKER_DIR)" % self.dm_qemu
            )
        cmd = [
            self.dm_qemu,
            "--iso", self.iso,
            "--emit-argv",
            "--verbose",
            "--entry", self.entry,
        ]
        if self.arch:
            cmd += ["--arch", self.arch]
        if self._qmp_sock:
            cmd += ["--qmp", self._qmp_sock]
        if self.fast:
            cmd.append("--fast")
        if self.memory is not None:
            cmd += ["--memory", str(self.memory)]
        if self.smp is not None:
            cmd += ["--smp", str(self.smp)]
        if self.extra_append:
            cmd += ["--extra-append", self.extra_append]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if proc.returncode != 0:
            raise SerialBootError(
                "dm-qemu --emit-argv failed (exit %s):\n%s"
                % (proc.returncode, proc.stderr.strip())
            )
        argv = [line for line in proc.stdout.splitlines() if line != ""]
        if not argv:
            raise SerialBootError("dm-qemu --emit-argv produced no argv")
        ## dm-qemu prints the extracted-kernel workdir to stderr; capture it so
        ## __exit__ can remove it (dm-qemu deliberately does NOT auto-clean it in
        ## --emit-argv mode, because the extracted kernel/initrd must outlive it).
        match = re.search(r"emit-argv workdir[^:]*:\s*(\S+)", proc.stderr)
        if match:
            self._workdir = match.group(1)
        return argv

    def __enter__(self):
        ## Any failure AFTER we start allocating (QMP temp dir, qemu child, QMP socket) must not
        ## leak: because __enter__ did not complete, the caller's 'with' body never runs and
        ## __exit__ is never called. Clean up and re-raise on any exception (e.g. _emit_argv
        ## raising SerialBootError because dm-qemu is missing, or pexpect.spawn failing).
        try:
            ## Allocate the QMP socket path BEFORE building the argv, so dm-qemu serves it.
            if self.use_qmp:
                self._qmp_dir = tempfile.mkdtemp(prefix="iso-boot-qmp-")
                self._qmp_sock = os.path.join(self._qmp_dir, "qmp.sock")
            argv = self._emit_argv()
            ## timeout here is the DEFAULT inter-expect timeout; each expect() below
            ## passes its own explicit, generous timeout.
            self.child = pexpect.spawn(
                argv[0],
                args=argv[1:],
                timeout=60,
                encoding="utf-8",
                codec_errors="replace",
                logfile=None,
            )
            if self.logfile is not None:
                ## Mirror the serial transcript for debugging (bytes stream).
                self.child.logfile_read = _TextToBinary(self.logfile)
            ## Connect QMP once qemu has created the socket. Best-effort: if it never appears (old
            ## dm-qemu without --qmp, or qemu died), degrade to serial-only power control.
            if self.use_qmp and self._qmp_sock:
                client = QMPClient(self._qmp_sock)
                if client.connect(timeout=60):
                    self.qmp = client
                else:
                    client.close()
                    self.qmp = None
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        if self.qmp is not None:
            self.qmp.close()
            self.qmp = None
        if self.child is not None and self.child.isalive():
            ## Best effort: ask qemu to quit via the monitor escape, then kill.
            try:
                self.child.close(force=True)
            except Exception:
                pass  ## qemu already exited / pexpect teardown race -- nothing to recover
        self.child = None
        if self._qmp_dir and os.path.isdir(self._qmp_dir):
            subprocess.run(["rm", "-rf", "--", self._qmp_dir], check=False)
            self._qmp_dir = None
        ## Resolve symlinks/'..' BEFORE the /tmp guard so a non-normalized path (the workdir comes
        ## from a loose regex over dm-qemu's stderr) cannot slip past it. dm-qemu is trusted, so
        ## this is defense-in-depth.
        if self._workdir:
            workdir_real = os.path.realpath(self._workdir)
            if workdir_real.startswith("/tmp/") and os.path.isdir(workdir_real):
                subprocess.run(["rm", "-rf", "--", workdir_real], check=False)
            self._workdir = None

    ## ----- interaction ---------------------------------------------------

    def wait_for_login(self, timeout=1800):
        """Block until the serial getty login prompt appears."""
        idx = self.child.expect(
            [r"[Ll]ogin:\s*$", pexpect.EOF, pexpect.TIMEOUT],
            timeout=timeout,
        )
        if idx == 1:
            raise SerialBootError("guest exited before reaching a login prompt")
        if idx == 2:
            raise SerialBootError(
                "no login prompt within %ss (guest hung or too slow)" % timeout
            )

    def login(self, timeout=300):
        """
        Log in as the configured user and confirm an interactive shell.

        Handles a PASSWORDLESS account (these live sessions log in with no password): a real
        getty prompt is 'Password:' (capital P) at the END of the stream; the login help text
        ('Default password: No password required', 'type the password') is lowercase and
        mid-line, so anchoring to a capital 'Password:' at line end avoids falsely matching it.
        If no real prompt appears (passwordless), the password step is skipped. Confirmation runs
        a marker command and waits for its exact echo, so it never depends on guessing the prompt.
        """
        self.child.sendline(self.username)
        ## Short timeout: a passwordless login shows no 'Password:' prompt, so fall through
        ## quickly instead of waiting the full timeout.
        idx = self.child.expect(
            [r"Password:\s*$", r"[Ll]ogin:\s*$", pexpect.TIMEOUT],
            timeout=min(timeout, 60),
        )
        if idx == 1:
            raise SerialBootError("login rejected the username '%s'" % self.username)
        if idx == 0:
            ## A real password prompt: send the password. (idx == 2 == passwordless: skip it.)
            self.child.sendline(self.password)

        ## The default interactive shell is zsh with ZLE + syntax highlighting + bracketed paste,
        ## which garbles a fast burst of serial input (characters doubled/reordered) so typed
        ## commands do not run intact. Drop to plain 'sh' (dash has no line editor) for a clean,
        ## predictable session; 'exec' leaves no nested shell. Slow-send so zsh reads it intact.
        ## Harmless if the shell is already a POSIX sh.
        self._send_slow("exec sh")

        ## Confirm an interactive shell via a marker (also catches a rejected login or a forced
        ## password change). In dash the command echoes cleanly, so the marker matches.
        login_ok = "%s_LOGIN_OK_%s" % (_MARK, self.username)
        self._send_slow("printf '%%s\\n' " + shlex.quote(login_ok))
        idx = self.child.expect(
            [
                re.escape(login_ok) + r"\r?\n",
                r"(?i)Login incorrect",
                r"(?i)you are required to change your password",
                pexpect.TIMEOUT,
            ],
            timeout=timeout,
        )
        if idx == 1:
            raise SerialBootError("login incorrect for '%s' (bad password?)" % self.username)
        if idx == 2:
            raise SerialBootError(
                "guest demands an immediate password change -- not handled"
            )
        if idx == 3:
            raise SerialBootError("logged in but no interactive shell appeared")

    def _send_slow(self, text, per_char=0.04):
        """Send a shell command one character at a time (then CR), pacing input so a remote
        interactive line editor (zsh ZLE + syntax highlighting) cannot garble a fast burst of
        serial input. Slower than sendline but reliable against a fancy login shell."""
        for char in text:
            self.child.send(char)
            time.sleep(per_char)
        self.child.send("\r")

    def run(self, command, timeout=1800, check=False):
        """
        Run one shell command in the logged-in session.

        Returns ``(output, returncode)``. ``output`` is everything the command
        printed (marker and echo stripped). If ``check`` is true, a non-zero
        return code raises SerialBootError.
        """
        mark = "%s_%d" % (_MARK, int(time.time() * 1000) % 1000000)
        ## Run the command, then emit "<mark>=<rc>" on its own line. Reading up to
        ## that marker bounds the output regardless of the prompt string. Slow-send so the input
        ## is not garbled if the session is still a ZLE shell.
        self._send_slow("%s; %s=$?; printf '%%s=%%s\\n' %s \"$%s\""
                        % (command, "__rc", shlex.quote(mark), "__rc"))
        idx = self.child.expect(
            [re.escape(mark) + r"=(\d+)\r?\n", pexpect.EOF, pexpect.TIMEOUT],
            timeout=timeout,
        )
        if idx == 1:
            raise SerialBootError("guest exited while running: %s" % command)
        if idx == 2:
            raise SerialBootError(
                "command timed out after %ss: %s" % (timeout, command)
            )
        returncode = int(self.child.match.group(1))
        output = self.child.before
        ## Strip the echoed command line (first line before output), best effort.
        output = _strip_command_echo(output, command)
        if check and returncode != 0:
            raise SerialBootError(
                "command failed (rc=%s): %s\n%s" % (returncode, command, output)
            )
        return output, returncode

    def poweroff(self, timeout=300):
        """
        Power the guest off and wait for qemu to exit. Prefers a QMP ACPI
        system_powerdown (clean, does not depend on the shell); falls back to a
        serial 'poweroff'. Returns the QMP shutdown reason if known.
        """
        if self.qmp is not None:
            resp = self.qmp.execute("system_powerdown")
            if resp is not None and "error" not in resp:
                reason = self.qmp.wait_for_shutdown(timeout)
                self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
                return reason
        self._shutdown("poweroff", timeout)
        return self.qmp.last_shutdown_reason if self.qmp is not None else None

    def reboot(self, timeout=300):
        """
        Reboot the guest (serial 'reboot'). dm-qemu passes ``-no-reboot``, so qemu
        EXITS on the guest reset -- this waits for that exit. When QMP is present,
        the SHUTDOWN event's reason confirms it was a reboot ('guest-reset') rather
        than a poweroff; the reason is returned. To boot the next session, create a
        fresh SerialBootSession with the desired ``entry``.
        """
        self.child.sendline("reboot")
        if self.qmp is not None:
            reason = self.qmp.wait_for_shutdown(timeout)
            self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
            return reason
        self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
        return None

    def _shutdown(self, verb, timeout):
        try:
            self.child.sendline(verb)
        except Exception:
            return
        self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)


class _TextToBinary:
    """Adapt a binary stream so pexpect's text logfile_read can write to it."""

    def __init__(self, binary_stream):
        self._stream = binary_stream

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        self._stream.write(data)

    def flush(self):
        try:
            self._stream.flush()
        except Exception:
            pass  ## a debug-mirror stream that can't flush must never break the boot session


def _strip_command_echo(output, command):
    """Drop the first line if it is the shell echoing the command we sent."""
    lines = output.splitlines()
    if lines and command.split(";")[0].strip() and command.split(";")[0].strip() in lines[0]:
        lines = lines[1:]
    return "\n".join(lines).strip("\r\n")
