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
export LC_ALL=C

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

## ABSENT SUBJECT, not a broken environment: dm-review-branch lives in the
## developer-meta-files checkout, so with no DMF_REPO there is nothing to judge.
## Self-skip (77) per the runner's absent-subject contract (and the meta-test
## test_dmf_runner_no_blanket_skip). Every prerequisite BELOW stays fail-closed,
## because those are defects in an environment whose subject IS present.
if [ -z "${DMF_REPO:-}" ]; then
   printf '%s\n' 'SKIP: test_dm_review_branch: DMF_REPO unset (no developer-meta-files checkout wired).' >&2
   ## style-ok: allow-skip: absent subject -- dm-review-branch lives in the DMF checkout; nothing to judge without DMF_REPO
   exit 77
fi

## The pty driver ships next to this script, so resolve it relative to this
## file (not PATH, not an install prefix): the suite runs from a checkout.
test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"
tty_driver="${test_dir}/dm_review_branch_tty.py"
## An unrunnable driver would exit non-zero, which case 4's 'no aborts'
## assertion accepts as success -- fail closed instead of passing on a defect.
assert_prerequisite \
   "'${tty_driver}' not found" \
   test -x "${tty_driver}"

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
   printf '%s\n' "FAIL: $1" >&2
   fail_count=$(( fail_count + 1 ))
}
pass() {
   printf '%s\n' "PASS: $1"
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
   printf '%s\n' '#!/bin/bash' 'exit 0' > "${work}/bin/$1"
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
printf '%s\n' 'first' > "${repo}/file"
git -C "${repo}" add file
git -C "${repo}" -c commit.gpgsign=false commit --no-verify --quiet --message 'initial'
git -C "${repo}" checkout --quiet -b feature
printf '%s\n' 'second' >> "${repo}/file"
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
printf '%s\n' 'third' >> "${repo}/file"
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
   ## Environment-only interface, matching the pty driver.
   REPO="${repo}" REF="$1" ANSWER="$2" "${tty_driver}"
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

## 5) After the operator CONSENTS to continue (case 4's 'yes' path), the raw
## commit message still reaches the terminal via 'git log'. It must be
## neutralized, or a commit message carrying a terminal escape injects the
## reviewer's terminal AFTER they waved the finding through. The payload is an
## SGR COLOR sequence specifically: stcat neutralizes cursor/erase escapes
## unconditionally, but KEEPS SGR when color is enabled -- so an attacker's
## black-on-black (concealment) survives a bare 'git log | stcat'. Only the
## tool's NO_COLOR=1 on that pipe closes it. Craft the message, answer 'yes' on
## a color terminal, capture the raw pty bytes, and assert the escape was
## rendered inert -- not passed through raw.
run_review_tty_capture() {
   ## $1 = ref, $2 = answer, $3 = capture path. Exit code = the tool's.
   ## Force a COLOR-capable terminal (TERM set, NO_COLOR unset) so the tool's
   ## own NO_COLOR=1 on the git-log stcat is the ONLY thing that can neutralize
   ## an SGR color sequence. Without this a no-color terminal makes stcat strip
   ## SGR anyway, and the assertion could not tell the fix from its absence
   ## (stcat neutralizes cursor/erase always, but keeps SGR when color is on).
   TERM=xterm-256color env --unset=NO_COLOR -- \
      REPO="${repo}" REF="$1" ANSWER="$2" CAPTURE="$3" "${tty_driver}"
}
git -C "${repo}" checkout --quiet -b esc feature
printf '%s\n' 'fourth' >> "${repo}/file"
## A distinctive ANSI payload: ESC '[31mINJECTED' ESC '[0m'. The unique
## 'INJECTED' tail lets the assertion match THIS sequence, so benign color
## escapes elsewhere in the output cannot mask a raw pass-through.
esc_msg="$(printf 'log injection \033[31mINJECTED\033[0m')"
git -C "${repo}" -c commit.gpgsign=false commit --no-verify --quiet --all \
   --message "${esc_msg}"
git -C "${repo}" checkout --quiet master
capture_file="${work}/esc-capture"
rc=0
run_review_tty_capture esc y "${capture_file}" || rc="$?"
raw_seq="$(printf '\033[31mINJECTED')"
neutralized_seq='_[31mINJECTED'
if [ "${rc}" != 0 ]; then
   fail "interactive yes on an ANSI commit message should continue (exit 0), got ${rc}"
elif [ ! -f "${capture_file}" ]; then
   fail 'no pty capture written for the ANSI commit-message case'
elif grep --fixed-strings --quiet -- "${raw_seq}" "${capture_file}"; then
   fail 'a raw ANSI escape from the commit message reached the terminal (git log not neutralized)'
elif ! grep --fixed-strings --quiet -- "${neutralized_seq}" "${capture_file}"; then
   fail 'the commit message never appeared neutralized; git log output not verified'
else
   pass 'ANSI in a consented commit message is neutralized in the git log (no raw escape to the terminal)'
fi

if [ "${fail_count}" -gt 0 ]; then
   printf '%s\n' "test_dm_review_branch: ${fail_count} assertion(s) failed." >&2
   exit 1
fi
printf '%s\n' 'test_dm_review_branch: OK -- commit-content and ref-name unicode scans both abort the review, and the consented-past git log is neutralized.'
