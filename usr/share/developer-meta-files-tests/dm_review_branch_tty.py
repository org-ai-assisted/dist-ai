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
##   REPO   -- repository to review in
##   REF    -- ref to review
##   ANSWER -- answer to feed the prompt ('y' or 'n')
##
## Exit code 124 means the prompt never appeared within the timeout and the
## child was killed -- always a suite failure, never a verdict.

import os
import pty
import select
import signal
import sys
import time

repo = os.environ["REPO"]
ref = os.environ["REF"]
ans = os.environ["ANSWER"].encode() + b"\n"

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

buf = b""
sent = False
timed_out = False
## Absolute cap as well as the per-read one: a child that keeps trickling
## output resets the select timeout forever, so idle-timeout alone is not a
## bound on this loop.
overall = time.monotonic() + 60
while True:
    if time.monotonic() > overall:
        timed_out = True
        break
    if not select.select([fd], [], [], 15)[0]:
        timed_out = True
        break
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    buf += data
    if not sent and b"Continue the review anyway" in buf:
        os.write(fd, ans)
        sent = True


## Reap without blocking forever. A child still sitting at its prompt (the
## expected text never arrived, so the answer was never sent) would otherwise
## make waitpid() hang for good -- the test must fail loud, not wedge.
##
## Signal the whole process GROUP, not just the direct child: pty.fork() makes
## the child a session leader, so its git and any pager it started share that
## group. Killing bash alone leaves them holding the pty open, and the final
## blocking waitpid is then the thing that hangs.
def reap_group():
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            ## Last-resort reap: the group kill above already failed, and the
            ## direct kill failing too means the child is gone (or unreachable).
            ## Either way the waitpid loop below is the thing that decides, so
            ## there is nothing left for this handler to do.
            pass


deadline = time.monotonic() + 10
while True:
    waited, status = os.waitpid(pid, os.WNOHANG)
    if waited:
        break
    if time.monotonic() > deadline:
        reap_group()
        ## Bounded even now: a reaped group should be immediate, but this must
        ## never be the call that wedges the suite.
        hard = time.monotonic() + 5
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited or time.monotonic() > hard:
                break
            time.sleep(0.05)
        timed_out = True
        break
    time.sleep(0.05)

if timed_out:
    sys.stderr.write(
        "run_review_tty: no 'Continue the review anyway' prompt within the "
        "timeout; child killed. Output was:\n"
        + buf.decode(errors="replace") + "\n")
    sys.exit(124)
sys.exit(os.waitstatus_to_exitcode(status))
