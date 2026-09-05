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
## '|| true': a cleanup failure must not abort the suite mid-run under errexit
## (that would silently drop the later cases with no PASS/FAIL summary).
git -C "${repo}" branch --delete --force -- "${spoof_name}" >/dev/null 2>&1 || true

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

## 6) The pty driver must NOT report 124 (a hang) for a child that answered the
## prompt and then went briefly quiet before exiting cleanly on its own. Drive a
## fake subject that prompts, reads the answer, sleeps PAST the (lowered) idle
## threshold, then exits 0: the driver's idle read fires, but the child is not
## wedged, so its real exit code (0) -- not 124 -- must be reported.
fake_dir="${work}/fake-subject"
mkdir -p "${fake_dir}"
cat > "${fake_dir}/dm-review-branch" <<'FAKE'
#!/bin/bash
printf 'Continue the review anyway?\n'
read -r _answer
sleep "${FAKE_QUIET_SECS:-2}"
## Write FAR more than a pty buffer (~64KB) so a driver that stops draining
## after the idle gap blocks us here indefinitely; then a marker the driver
## must still capture, proving it drained to EOF rather than dropping tail bytes.
head -c 200000 /dev/zero | tr '\0' x
printf '\nPOSTGAP-MARKER-DONE\n'
exit 0
FAKE
chmod +x "${fake_dir}/dm-review-branch"
capture6="${work}/case6-capture"
rc=0
PATH="${fake_dir}:${PATH}" RUN_REVIEW_IDLE_SECS=1 FAKE_QUIET_SECS=2 \
   REPO="${repo}" REF=x ANSWER=y CAPTURE="${capture6}" "${tty_driver}" >/dev/null 2>&1 || rc="$?"
if [ "${rc}" != 0 ]; then
   fail "driver should report the child's real 0 after a large post-gap write, got ${rc}"
elif [ ! -f "${capture6}" ] || ! grep --fixed-strings --quiet -- 'POSTGAP-MARKER-DONE' "${capture6}"; then
   fail 'driver dropped post-gap output (did not drain the pty to EOF)'
else
   pass 'driver drains large post-gap output and reports the real exit (0), not 124'
fi

## 7) A scan SETUP error (rc >= 2: a nonexistent/typo'd ref) must fail closed
## with the real error, NOT be mislabeled "possible unicode spoofing" and NOT
## trigger a pointless "continue anyway?" prompt for a review that cannot run.
scan_err="${work}/scan-err"
rc=0
( cd -- "${repo}" && setsid dm-review-branch definitely-not-a-real-ref-xyz ) \
   </dev/null >"${scan_err}" 2>&1 || rc="$?"
if [ "${rc}" = 0 ]; then
   fail 'reviewing a nonexistent ref should fail (non-zero), but it exited 0'
elif [ "${rc}" -lt 2 ]; then
   fail "a scan setup error must exit >= 2 (the scan-error code, not the rc-1 detection code), got ${rc}"
elif grep --ignore-case --quiet -- 'possible unicode spoofing' "${scan_err}"; then
   fail 'a nonexistent-ref setup error was mislabeled "possible unicode spoofing"'
elif grep --ignore-case --quiet -- 'continue the review anyway' "${scan_err}"; then
   fail 'a nonexistent-ref setup error triggered a pointless continue-prompt'
else
   pass 'a scan setup error (rc >= 2) fails closed with the real error, not a spoofing prompt'
fi

## 8) A missing scan dependency (unicode-show) must fail closed EARLY with a
## clear message -- never reach the scan-consent prompt with a non-functioning
## scanner. check-ref-*-for-unicode return a MISLEADING rc 1 (die_if_not_has)
## when unicode-show is absent, which the rc==1 path would take for a detection
## and let the operator wave past. Mirror every tool EXCEPT unicode-show onto a
## PATH so the guard sees it as genuinely absent while the rest stay present.
noshow_dir="${work}/no-unicode-show"
mkdir -p "${noshow_dir}"
mirror_bins() {
   local d="$1" real
   [ -d "${d}" ] || return 0
   for real in "${d}"/*; do
      ## Regular executables only: skip a symlink-to-directory such as
      ## '/usr/bin/X11' -- it is not a tool, and --force would dereference an
      ## already-mirrored one and try to create INSIDE the read-only dir.
      [ -f "${real}" ] || continue
      ## --no-dereference so re-mirroring a name (e.g. /bin and /usr/bin both
      ## carry it on a merged-usr system) replaces the link, never follows it.
      ln --symbolic --force --no-dereference -- "${real}" "${noshow_dir}/${real##*/}"
   done
}
mirror_bins /usr/bin
mirror_bins /bin
mirror_bins "${DMF_REPO}/usr/bin"
if [ -n "${HELPER_SCRIPTS_PATH:-}" ]; then
   mirror_bins "${HELPER_SCRIPTS_PATH}/usr/bin"
fi
safe-rm --force -- "${noshow_dir}/unicode-show"
guard_out="${work}/guard-out"
rc=0
( cd -- "${repo}" && PATH="${noshow_dir}" setsid dm-review-branch feature ) \
   </dev/null >"${guard_out}" 2>&1 || rc="$?"
if [ "${rc}" = 0 ]; then
   fail 'a missing unicode-show should fail the review closed, but it exited 0'
elif grep --ignore-case --quiet -- 'continue the review anyway' "${guard_out}"; then
   fail 'a missing unicode-show reached the continue-prompt instead of failing closed'
elif ! grep --ignore-case --quiet -- 'unicode-show' "${guard_out}"; then
   fail 'a missing unicode-show did not produce a clear diagnostic naming it'
else
   pass 'a missing unicode-show fails closed early with a clear message, no prompt'
fi

## 9) Zero arguments must produce a clear usage message and fail closed, not a
## bare 'unbound variable' nounset crash.
noarg_out="${work}/noarg-out"
rc=0
( cd -- "${repo}" && dm-review-branch ) </dev/null >"${noarg_out}" 2>&1 || rc="$?"
if [ "${rc}" = 0 ]; then
   fail 'dm-review-branch with no argument should fail, but it exited 0'
elif grep --quiet -- 'unbound variable' "${noarg_out}"; then
   fail 'dm-review-branch with no argument crashed on nounset instead of a usage message'
elif ! grep --ignore-case --quiet -- 'usage' "${noarg_out}"; then
   fail 'dm-review-branch with no argument did not print a usage message'
else
   pass 'dm-review-branch with no argument fails closed with a usage message'
fi

## 10) A leading-dash ref must be rejected by dm-review-branch itself (defense in
## depth), never passed bare to check-ref-commits-for-unicode where it could be
## misparsed as an option.
dash_out="${work}/dash-out"
rc=0
( cd -- "${repo}" && dm-review-branch -x ) </dev/null >"${dash_out}" 2>&1 || rc="$?"
if [ "${rc}" = 0 ]; then
   fail 'dm-review-branch with a leading-dash ref should fail, but it exited 0'
elif ! grep --ignore-case --quiet -- "must not start with" "${dash_out}"; then
   fail 'a leading-dash ref was not rejected by dm-review-branch itself'
else
   pass 'dm-review-branch rejects a leading-dash ref up front'
fi

## 11) 'set -x' must be OFF: xtrace echoes every command's EXPANDED form to the
## terminal, so an untrusted ref name (git permits U+202E in a ref) would reach
## the operator RAW, before any scan or stcat neutralization. Review a
## nonexistent U+202E ref and assert its raw bytes never appear in the output.
xtrace_out="${work}/xtrace-out"
u202e_ref="$(printf 'evil\xe2\x80\xaeref')"
rc=0
( cd -- "${repo}" && dm-review-branch "${u202e_ref}" ) </dev/null >"${xtrace_out}" 2>&1 || rc="$?"
if [ "${rc}" = 0 ]; then
   fail 'reviewing a nonexistent U+202E ref should fail, but it exited 0'
elif grep --fixed-strings --quiet -- "$(printf '\xe2\x80\xae')" "${xtrace_out}"; then
   fail 'a raw U+202E ref name reached the terminal (xtrace leak -- set -x on?)'
else
   pass 'no raw ref name leaks to the terminal (set -x is off)'
fi

if [ "${fail_count}" -gt 0 ]; then
   printf '%s\n' "test_dm_review_branch: ${fail_count} assertion(s) failed." >&2
   exit 1
fi
printf '%s\n' 'test_dm_review_branch: OK -- unicode scans abort the review, the consented-past git log is neutralized, the pty driver does not false-time-out, a scan setup error fails closed cleanly, and a missing scan dependency fails closed early.'
