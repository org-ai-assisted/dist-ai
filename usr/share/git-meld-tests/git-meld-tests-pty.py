#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Run a command under a pseudo-terminal (so the command sees a real controlling
## tty / /dev/tty), feed a canned answer to every prompt line containing
## "QUESTION", and report the command's exit code. Used to drive
## git-diff-review's interactive "continue past neutralized fatal content? [y/N]"
## prompt from the git-meld-tests suite.
##
## usage: git-meld-tests-pty.py <answer[,answer...]> <cmd> [args...]   (run from
## the cwd the command should execute in). <answer> may be a comma-separated
## SEQUENCE applied one per prompt in order (the last is reused for any further
## prompts), so a tool with more than one prompt -- e.g. git-diff-review's
## "proceed to the per-file diffs?" gate FOLLOWED by its fatal-content "continue
## anyway?" prompt -- can be driven distinctly ('y,n' = proceed, then decline). A
## bare single answer answers every prompt with it, unchanged. Prints
## PTY_EXITCODE=<n>, PTY_ANSWERED=<count>, PTY_CONTINUED=<bool> to stdout.
## PTY_EXITCODE=timeout means the command was still running at the deadline and
## got killed -- always a suite failure, never a verdict.

import os
import pty
import select
import signal
import sys
import time

## Generous: the driven review takes a few seconds. A command that outlives this
## is stuck on something no answer can satisfy (a pager waiting for a keypress,
## an unanswered prompt), and the suite must fail loudly rather than wedge.
DEADLINE_SECONDS = 30

answers = [a.encode() + b'\n' for a in sys.argv[1].split(',')]
cmd = sys.argv[2:]

pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)

out = b''
answered = 0
timed_out = False
deadline = time.monotonic() + DEADLINE_SECONDS
while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        timed_out = True
        break
    try:
        ready, _, _ = select.select([fd], [], [], remaining)
    except OSError:
        break
    if not ready:
        timed_out = True
        break
    try:
        data = os.read(fd, 4096)
    except OSError:
        ## The child closed the pty (it exited); EIO is the normal end here.
        break
    if not data:
        break
    out += data
    ## Answer EVERY prompt, not just the first: the driver asks once per finding,
    ## and an unanswered later prompt would leave the child blocked on /dev/tty.
    ## Each new prompt consumes the next answer in the sequence, clamped to the
    ## last, so a single answer still answers every prompt with it.
    count = out.count(b'QUESTION')
    while answered < count:
        os.write(fd, answers[min(answered, len(answers) - 1)])
        answered += 1

## Never waitpid() a live child unconditionally -- that is what turned a stuck
## command into an unkillable suite hang.
if timed_out:
    os.kill(pid, signal.SIGKILL)
waited_pid, status = os.waitpid(pid, 0)
code = 'timeout' if timed_out else os.waitstatus_to_exitcode(status)
continued = b'stcat-neutralized' in out or b'@@' in out
sys.stdout.write('PTY_EXITCODE=%s\n' % code)
sys.stdout.write('PTY_ANSWERED=%s\n' % answered)
sys.stdout.write('PTY_CONTINUED=%s\n' % continued)
