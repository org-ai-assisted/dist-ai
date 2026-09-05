#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drive developer-meta-files' dm-review-branch under a pseudo-terminal so its
## interactive "Continue the review anyway?" prompt (which reads /dev/tty) is
## reachable, answer that prompt once, and exit with the tool's own exit code.
## Used by test_dm_review_branch.sh for the interactive cases.
##
## Interface is environment-only (no argv), so the shell side can set it inline:
##   REPO    -- repository to review in
##   REF     -- ref to review
##   ANSWER  -- answer to feed the prompt ('y' or 'n')
##   CAPTURE -- optional path; when set, the child's raw pty output (every byte
##              the terminal would have received) is written there, so a caller
##              can assert what actually reached the terminal (e.g. that no raw
##              escape byte survived neutralization).
##   RUN_REVIEW_IDLE_SECS -- per-read idle threshold (default 15); a test can
##              lower it to exercise the "answered then briefly quiet before a
##              clean exit" path without a real 15s wait.
##
## Exit code 124 means the child never made progress: the prompt never appeared
## (so the answer was never sent) OR the child had to be SIGKILLed as genuinely
## wedged -- always a suite failure, never a verdict. A child that answers the
## prompt and then goes briefly quiet before exiting on its OWN reports its own
## exit code, not 124 (a quiet post-prompt gap is not a hang).

import os
import pty
import select
import signal
import sys
import time

repo = os.environ["REPO"]
ref = os.environ["REF"]
ans = os.environ["ANSWER"].encode() + b"\n"
capture = os.environ.get("CAPTURE", "")
idle_secs = float(os.environ.get("RUN_REVIEW_IDLE_SECS", "15"))

pid, fd = pty.fork()
if pid == 0:
    try:
        os.chdir(repo)
        ## dm-review-branch runs 'git log'. On a pty git starts its pager,
        ## which waits for input that never comes, so the tool never exits and
        ## the pty never reaches EOF. GIT_PAGER/PAGER alone are not enough:
        ## anything that re-execs git through a sanitized environment drops
        ## them and git falls back to its compiled-in default pager. The
        ## GIT_CONFIG_* triple injects core.pager as real config, which every
        ## git in the subtree honours and no repo config can override.
        os.environ["GIT_PAGER"] = "cat"
        os.environ["PAGER"] = "cat"
        os.environ["GIT_CONFIG_COUNT"] = "1"
        os.environ["GIT_CONFIG_KEY_0"] = "core.pager"
        os.environ["GIT_CONFIG_VALUE_0"] = "cat"
        os.environ["GIT_TERMINAL_PROMPT"] = "0"
        os.execvp("dm-review-branch", ["dm-review-branch", ref])
    finally:
        ## execvp only returns on failure; never fall back into the parent's
        ## code path, and never leave a forked child alive on error.
        os._exit(127)

## Signal the whole process GROUP, not just the direct child: pty.fork() makes
## the child a session leader, so its git and any pager it started share that
## group. Killing bash alone leaves them holding the pty open.
def reap_group():
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            ## The group kill failed and so did the direct kill: the child is
            ## gone or unreachable, so the waitpid below is what decides.
            pass


buf = b""
sent = False
killed = False


def reap(force):
    """Collect the child's wait status, bounded. force=True SIGKILLs first (and
    sets `killed`); force=False waits for a clean exit and escalates to a kill
    only if it overstays. Returns the wait status (0 if it cannot be collected)."""
    global killed
    if force:
        reap_group()
        killed = True
    deadline = time.monotonic() + 10
    while True:
        waited, st = os.waitpid(pid, os.WNOHANG)
        if waited:
            return st
        if time.monotonic() > deadline:
            return reap(True) if not force else 0
        time.sleep(0.05)


## Drain the pty CONTINUOUSLY while waiting for the child, so a child that
## writes more than the pty buffer after a quiet gap never blocks on write()
## (which would look like a hang, losing its real exit code AND dropping later
## output from `buf`). The loop ends when the child exits (its own status) or a
## hard cap is blown (wedged -> SIGKILL, 124). idle_secs bounds a single read;
## `overall` bounds the whole wait so a forever-trickling child cannot run on.
status = None
overall = time.monotonic() + 60
while status is None:
    if time.monotonic() > overall:
        status = reap(True)
        break
    if select.select([fd], [], [], idle_secs)[0]:
        try:
            data = os.read(fd, 65536)
        except OSError:
            ## Linux raises EIO on the master once the child closes the slave.
            data = b""
        if data:
            buf += data
            if not sent and b"Continue the review anyway" in buf:
                os.write(fd, ans)
                sent = True
            continue
        ## EOF: the child closed the pty and will not write again -- reap it.
        status = reap(False)
        break
    ## Idle interval with nothing to read: did the child exit on its own?
    waited, st = os.waitpid(pid, os.WNOHANG)
    if waited:
        status = st
        break
    ## Child alive and merely quiet (a legitimate sleep) -- keep draining.

## Persist the raw terminal bytes for the caller's inspection, before any
## timeout exit -- a truncated capture is still evidence of what reached the tty.
if capture:
    with open(capture, "wb") as capture_file:
        capture_file.write(buf)

## 124 ONLY when the child never made progress: it had to be SIGKILLed as wedged,
## or the prompt never appeared (so the answer was never sent). A child that
## answered and then exited on its own -- even after a quiet gap -- reports its
## real exit code; a post-prompt quiet spell is not a hang.
if killed or not sent:
    reason = ("child wedged; SIGKILLed"
              if killed
              else "no 'Continue the review anyway' prompt appeared")
    sys.stderr.write(
        "run_review_tty: " + reason + ". Output was:\n"
        + buf.decode(errors="replace") + "\n")
    sys.exit(124)
sys.exit(os.waitstatus_to_exitcode(status))
