#!/usr/bin/python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Fast serial-console iteration harness for developing dm-image-test checks.

Boot an image ONCE with the serial redirected to a UNIX socket, leave qemu
running, and CONNECT repeatedly to experiment with login/command logic WITHOUT
rebooting (each boot is minutes under pure-TCG). The image is booted with
dm-qemu --test-console, so systemd's debug-shell binds a login-free ROOT bash to
the serial line: a fresh connection always finds a usable shell, and no
interactive user zsh is in the way.

    dmserial.py boot  <disk-or-iso> ["extra smbios kernel params"]
    dmserial.py poke  "shell command"     # connect, run, print the reply
    dmserial.py raw                        # dump what the console shows now
    dmserial.py kill                       # stop qemu

dm-qemu is resolved from $DM_QEMU, else the sibling copy next to this script
(the dm-image-boot-tests suite), else PATH. State (socket, pidfile, boot log,
the recorded image path) lives under $DMSERIAL_WORK, else
${XDG_RUNTIME_DIR:-/tmp}/dmserial.
"""

import os
import socket
import subprocess
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WORK = os.environ.get("DMSERIAL_WORK") or os.path.join(
    os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "dmserial")
SOCK = os.path.join(WORK, "dmserial.sock")
PIDFILE = os.path.join(WORK, "dmserial.pid")
BOOTLOG = os.path.join(WORK, "boot.log")
IMAGEFILE = os.path.join(WORK, "image")


def dm_qemu():
    """dm-qemu: $DM_QEMU, else the sibling in the suite (../dm-qemu), else PATH."""
    env = os.environ.get("DM_QEMU")
    if env:
        return env
    sibling = os.path.join(os.path.dirname(SCRIPT_DIR), "dm-qemu")
    return sibling if os.path.isfile(sibling) else "dm-qemu"


def emit_argv(image, smbios_extra):
    ## --disk for a VM image, --iso for a live ISO (crude but sufficient here).
    source = "--iso" if image.lower().endswith(".iso") else "--disk"
    cmd = [dm_qemu(), source, image, "--arch", "amd64", "--firmware", "bios",
           "--test-console", "--fast", "--memory", "1024"]
    if smbios_extra:
        cmd += ["--smbios-append", smbios_extra]
    cmd += ["--emit-argv"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def do_boot(image, smbios_extra):
    os.makedirs(WORK, exist_ok=True)
    argv = emit_argv(image, smbios_extra)
    ## Redirect the serial to a UNIX socket instead of stdio (-nographic).
    argv = [a for a in argv if a != "-nographic"]
    argv += ["-display", "none",
             "-serial", "unix:%s,server,nowait" % SOCK,
             "-monitor", "none"]
    for path in (SOCK, BOOTLOG):
        try:
            os.unlink(path)
        except OSError:
            pass
    logf = open(BOOTLOG, "wb")
    proc = subprocess.Popen(argv, stdout=logf, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    open(PIDFILE, "w").write(str(proc.pid))
    open(IMAGEFILE, "w").write(image)
    print("booted qemu pid %d; serial socket %s (image %s)"
          % (proc.pid, SOCK, image))


def connect(timeout=8.0):
    deadline = time.time() + 120
    while not os.path.exists(SOCK):
        if time.time() > deadline:
            raise SystemExit("serial socket never appeared (qemu not up?)")
        time.sleep(0.5)
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(timeout)
    while True:
        try:
            sock.connect(SOCK)
            break
        except OSError:
            if time.time() > deadline:
                raise SystemExit("could not connect to serial socket")
            time.sleep(0.5)
    return sock


def drain(sock, seconds):
    """Read whatever the console emits for N seconds; return the text."""
    buf = []
    end = time.time() + seconds
    sock.settimeout(0.5)
    while time.time() < end:
        try:
            data = sock.recv(65536)
            if data:
                buf.append(data)
        except socket.timeout:
            pass
        except OSError:
            break
    return b"".join(buf).decode("utf-8", "replace")


def do_raw():
    sock = connect()
    sock.sendall(b"\r")
    print(drain(sock, 3))


def do_poke(command):
    """Run one command over the current console and print the reply. A split
    token keeps the delimiter apart in the echo, so only the shell's real OUTPUT
    prints 'DMX<pid>[...]DMX<pid>'."""
    sock = connect()
    sock.sendall(b"\r")
    time.sleep(0.5)
    drain(sock, 1)
    tok = "DMX%d" % os.getpid()
    line = "%s; printf '%s[%%s]%s\\n' \"$?\"\r" % (command, tok, tok)
    sock.sendall(line.encode())
    out = drain(sock, 8)
    print("----- raw reply -----")
    print(repr(out[-600:]))


def do_kill():
    try:
        pid = int(open(PIDFILE).read())
        os.kill(pid, 9)
        print("killed", pid)
    except (OSError, ValueError) as exc:
        print("nothing to kill:", exc)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    action = sys.argv[1]
    if action == "boot":
        if len(sys.argv) < 3:
            raise SystemExit("usage: dmserial.py boot <disk-or-iso> [smbios extra]")
        do_boot(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    elif action == "poke":
        if len(sys.argv) < 3:
            raise SystemExit("usage: dmserial.py poke \"shell command\"")
        do_poke(sys.argv[2])
    elif action == "raw":
        do_raw()
    elif action == "kill":
        do_kill()
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
