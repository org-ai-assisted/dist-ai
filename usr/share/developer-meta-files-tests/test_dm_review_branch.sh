#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for developer-meta-files' dm-review-branch: it must scan a
## reviewed branch's new commits AND every ref NAME for suspicious non-ASCII
## unicode before showing the diff, and abort (non-zero) when either is found.
## The GUI/log steps (git log, git-diff-review, git-meld, git-kdiff3) are
## stubbed so the security path runs headless.
##
## Regression guard: dm-review-branch once passed the reviewed ref straight to
## check-ref-names-for-unicode, which takes ref-name GLOBS -- so a spoofed
## SIBLING ref name was never scanned (and a look-alike reviewed name made
## for-each-ref error rather than flag). This test creates a spoofed sibling
## and asserts the review halts.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source /usr/libexec/helper-scripts/has.sh

## Fail closed. A missing prerequisite is an environment defect: skipping on
## it reports green while the test never ran, which is worse than no test.
assert_prerequisite() {
   local description

   description="$1"
   shift

   if ! "$@"; then
      printf '%s\n' "FATAL: test_dm_review_branch: ${description}" >&2
      exit 1
   fi
}

assert_prerequisite \
   'DMF_REPO unset (run via the developer-meta-files-tests entrypoint)' \
   test -n "${DMF_REPO:-}"

## dm-review-branch drives check-ref-commits-for-unicode / check-ref-names-for-
## unicode / unicode-show (helper-scripts).
for tool in check-ref-commits-for-unicode check-ref-names-for-unicode unicode-show git setsid; do
   assert_prerequisite "'${tool}' not on PATH" has "${tool}"
done
assert_prerequisite \
   "'${DMF_REPO}/usr/bin/dm-review-branch' not found" \
   test -x "${DMF_REPO}/usr/bin/dm-review-branch"

fail_count=0
fail() {
   printf 'FAIL: %s\n' "$1" >&2
   fail_count=$(( fail_count + 1 ))
}
pass() {
   printf 'PASS: %s\n' "$1"
}

work="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## Stub the GUI / log steps so only the unicode-scan security path runs. Put
## the developer-meta-files checkout's dm-review-branch ahead of any installed
## copy so we exercise the code under review.
mkdir -p "${work}/bin"
stub() {
   printf '#!/bin/bash\nexit 0\n' > "${work}/bin/$1"
   chmod +x "${work}/bin/$1"
}
stub git-meld
stub git-kdiff3
stub git-diff-review
export PATH="${work}/bin:${DMF_REPO}/usr/bin:${PATH}"

## Build a throwaway repo: master, and a feature branch with one clean new
## commit to review. --no-verify so a local commit-msg unicode hook (if any)
## does not interfere with the deliberately-crafted cases below.
repo="${work}/repo"
git init --quiet -- "${repo}"
git -C "${repo}" config user.email 'test@example.com'
git -C "${repo}" config user.name 'test'
printf 'first\n' > "${repo}/file"
git -C "${repo}" add file
git -C "${repo}" -c commit.gpgsign=false commit --no-verify --quiet --message 'initial'
git -C "${repo}" checkout --quiet -b feature
printf 'second\n' >> "${repo}/file"
git -C "${repo}" -c commit.gpgsign=false commit --no-verify --quiet --all --message 'a clean new line'
git -C "${repo}" checkout --quiet master

run_review() {
   ## Run dm-review-branch inside the repo, capture its exit code. setsid drops
   ## the controlling terminal so the continue-prompt on a unicode-scan failure
   ## fails closed (non-zero) rather than blocking on /dev/tty.
   ( cd -- "${repo}" && setsid dm-review-branch "$1" ) </dev/null >/dev/null 2>&1
}

## 1) A clean branch with a clean new commit: the review completes (exit 0).
rc=0
run_review feature || rc="$?"
if [ "${rc}" = 0 ]; then
   pass 'clean branch review completes (exit 0)'
else
   fail "clean branch review should exit 0, got ${rc}"
fi

## 2) A spoofed SIBLING branch name (U+202E RIGHT-TO-LEFT OVERRIDE): the review
## must abort non-zero. This is the regression the glob fix addresses -- a
## sibling ref, not the reviewed one.
spoof_name="$(printf 'evil\xe2\x80\xaebranch')"
git -C "${repo}" branch -- "${spoof_name}" master
rc=0
run_review feature || rc="$?"
if [ "${rc}" != 0 ]; then
   pass 'spoofed sibling ref name aborts the review (non-zero)'
else
   fail 'a ref name with U+202E must abort the review, but it exited 0'
fi
git -C "${repo}" branch --delete --force -- "${spoof_name}" >/dev/null 2>&1

## 3) Non-ASCII unicode in a commit MESSAGE on the reviewed branch: the review
## must abort non-zero (check-ref-commits-for-unicode).
git -C "${repo}" checkout --quiet -b dirty feature
printf 'third\n' >> "${repo}/file"
git -C "${repo}" -c commit.gpgsign=false commit --no-verify --quiet --all \
   --message "$(printf 'sneaky \xe2\x80\xae message')"
git -C "${repo}" checkout --quiet master
rc=0
run_review dirty || rc="$?"
if [ "${rc}" != 0 ]; then
   pass 'unicode in a commit message aborts the review (non-zero)'
else
   fail 'a commit message with U+202E must abort the review, but it exited 0'
fi

## 4) Interactive continue-prompt: when a unicode scan fails AND there is a
## terminal, dm-review-branch asks "Continue the review anyway?" -- yes proceeds
## (exit 0), no aborts (non-zero). Drive it over a pty. python3 is assumed
## present; if it is absent these cases fail loud rather than silently skip.
run_review_tty() {
   ## $1 = ref to review, $2 = answer ('y'|'n'). Exit code = the tool's.
   REPO="${repo}" REF="$1" ANSWER="$2" python3 -- - <<'PYEOF'
import os, sys, pty, select, signal, time
repo = os.environ["REPO"]; ref = os.environ["REF"]
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
buf = b""; sent = False
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
        os.write(fd, ans); sent = True

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
PYEOF
}
rc=0
run_review_tty dirty y || rc="$?"
if [ "${rc}" = 0 ]; then
   pass 'interactive: answering yes continues the review (exit 0)'
else
   fail "interactive yes should continue (exit 0), got ${rc}"
fi
rc=0
run_review_tty dirty n || rc="$?"
if [ "${rc}" != 0 ]; then
   pass 'interactive: answering no aborts the review (non-zero)'
else
   fail 'interactive no should abort the review, but it exited 0'
fi

if [ "${fail_count}" -gt 0 ]; then
   printf 'test_dm_review_branch: %d assertion(s) failed.\n' "${fail_count}" >&2
   exit 1
fi
printf 'test_dm_review_branch: OK -- commit-content and ref-name unicode scans both abort the review.\n'
