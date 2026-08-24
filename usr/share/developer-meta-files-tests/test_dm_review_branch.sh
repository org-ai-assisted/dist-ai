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
## 77 is the runner's skip contract. Every prerequisite BELOW stays fail-closed,
## because those are defects in an environment whose subject IS present.
if [ -z "${DMF_REPO:-}" ]; then
   printf '%s\n' 'FATAL: test_dm_review_branch: DMF_REPO unset (no developer-meta-files checkout wired).' >&2
   exit 1
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

if [ "${fail_count}" -gt 0 ]; then
   printf '%s\n' "test_dm_review_branch: ${fail_count} assertion(s) failed." >&2
   exit 1
fi
printf '%s\n' 'test_dm_review_branch: OK -- commit-content and ref-name unicode scans both abort the review.'
