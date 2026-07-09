#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run a command under a pseudo-terminal (so the command sees a real controlling
## tty / /dev/tty), feed a canned answer the first time the command prints a
## line containing "QUESTION", and report the command's exit code. Used to drive
## git-diff-review's interactive "continue past neutralized fatal content? [y/N]"
## prompt from the git-meld-tests suite.
##
## usage: git-meld-tests-pty.py <answer> <cmd> [args...]   (run from the cwd the
## command should execute in). Prints PTY_EXITCODE=<n>, PTY_ANSWERED=<bool>,
## PTY_CONTINUED=<bool> to stdout.

import os
import pty
import select
import sys

answer = sys.argv[1].encode() + b"\n"
cmd = sys.argv[2:]

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
else:
    out = b""
    sent = False
    while True:
        try:
            ready, _, _ = select.select([fd], [], [], 20)
        except OSError:
            break
        if not ready:
            break
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
        if not sent and b"QUESTION" in out:
            os.write(fd, answer)
            sent = True
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    continued = b"stcat-neutralized" in out or b"@@" in out
    sys.stdout.write("PTY_EXITCODE=%d\n" % code)
    sys.stdout.write("PTY_ANSWERED=%s\n" % sent)
    sys.stdout.write("PTY_CONTINUED=%s\n" % continued)
