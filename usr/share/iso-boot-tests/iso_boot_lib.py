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
import sys
import tempfile
import time

import pexpect


class SerialBootError(RuntimeError):
    """A step of the serial boot / login / command sequence failed."""


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
        ## Greeting: {"QMP": {...}}. Then enter command mode.
        greeting = self._read_message()
        if not greeting or "QMP" not in greeting:
            self.close()
            return False
        resp = self.execute("qmp_capabilities")
        return resp is not None and "error" not in resp

    def _read_message(self):
        """Read one JSON object (one line). Returns the parsed dict, or None on EOF."""
        line = self._rfile.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            return {}
        return json.loads(line)

    def execute(self, command, arguments=None, timeout=30):
        """Send a command and return its response dict ({'return': ...} or {'error': ...}).
        Asynchronous events (e.g. SHUTDOWN) that arrive first are recorded and skipped."""
        if self._sock is None:
            return None
        msg = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        self._sock.sendall((json.dumps(msg) + "\r\n").encode("utf-8"))
        self._sock.settimeout(timeout)
        while True:
            reply = self._read_message()
            if reply is None:
                return None
            if "event" in reply:
                self._record_event(reply)
                continue
            return reply

    def wait_for_shutdown(self, timeout=300):
        """Block until a SHUTDOWN event (or EOF). Returns the reason string
        ('guest-reset' for a reboot, 'guest-shutdown' for an ACPI poweroff), or None."""
        if self._sock is None:
            return None
        self._sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = self._read_message()
            except (socket.timeout, TimeoutError):
                return None
            if event is None:
                return self.last_shutdown_reason
            if "event" in event:
                self._record_event(event)
                if event.get("event") == "SHUTDOWN":
                    return self.last_shutdown_reason
        return None

    def _record_event(self, event):
        if event.get("event") == "SHUTDOWN":
            self.last_shutdown_reason = event.get("data", {}).get("reason")

    def close(self):
        if self._rfile is not None:
            try:
                self._rfile.close()
            except OSError:
                pass
            self._rfile = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
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
        ## Allocate the QMP socket path BEFORE building the argv, so dm-qemu is told to serve it.
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
                pass
        self.child = None
        if self._qmp_dir and os.path.isdir(self._qmp_dir):
            subprocess.run(["rm", "-rf", "--", self._qmp_dir], check=False)
            self._qmp_dir = None
        if self._workdir and self._workdir.startswith("/tmp/") and os.path.isdir(self._workdir):
            subprocess.run(["rm", "-rf", "--", self._workdir], check=False)
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

        Confirmation does not rely on guessing the prompt: it runs a marker
        command and waits for that exact marker to echo back.
        """
        self.child.sendline(self.username)
        idx = self.child.expect(
            [r"[Pp]assword:\s*", r"[Ll]ogin:\s*$", pexpect.TIMEOUT],
            timeout=timeout,
        )
        if idx == 1:
            raise SerialBootError("login rejected the username '%s'" % self.username)
        if idx == 2:
            raise SerialBootError("no password prompt after sending the username")
        self.child.sendline(self.password)

        ## A forced first-login password change would show up here instead of a
        ## shell; detect it explicitly rather than hanging until timeout.
        login_ok = "%s_LOGIN_OK_%s" % (_MARK, self.username)
        self.child.sendline("printf '%%s\\n' " + shlex.quote(login_ok))
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

    def run(self, command, timeout=1800, check=False):
        """
        Run one shell command in the logged-in session.

        Returns ``(output, returncode)``. ``output`` is everything the command
        printed (marker and echo stripped). If ``check`` is true, a non-zero
        return code raises SerialBootError.
        """
        mark = "%s_%d" % (_MARK, int(time.time() * 1000) % 1000000)
        ## Run the command, then emit "<mark>=<rc>" on its own line. Reading up to
        ## that marker bounds the output regardless of the prompt string.
        self.child.sendline("%s; %s=$?; printf '%%s=%%s\\n' %s \"$%s\""
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
            pass


def _strip_command_echo(output, command):
    """Drop the first line if it is the shell echoing the command we sent."""
    lines = output.splitlines()
    if lines and command.split(";")[0].strip() and command.split(";")[0].strip() in lines[0]:
        lines = lines[1:]
    return "\n".join(lines).strip("\r\n")
