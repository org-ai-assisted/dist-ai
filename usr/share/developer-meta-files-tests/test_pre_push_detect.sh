#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Truth-table test for pre-push-detect, the parser-backed style detector (over
## the shfmt AST via dist_ai.bash_ast / dist_ai.detect). Drives the REAL shipped
## tool as a subprocess. The point: a command is told from data that only LOOKS
## like one -- inside a string, a heredoc, an array, or after a 'VAR=value' /
## 'sudo' prefix -- which the former regex gate could only approximate. Each
## fixture line is placed so its expected finding (or absence) is asserted by
## rule tag + line number.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
DET="${tool_test_dir}/../../bin/pre-push-detect"
if [ ! -x "${DET}" ]; then
   DET='/usr/bin/pre-push-detect'
fi
for prereq in python3 shfmt ; do
   if ! type -P "${prereq}" >/dev/null 2>&1 ; then
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   fi
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

passc=0
fail=0
note_pass() { printf '%s\n' "PASS: ${1}" ; passc=$(( passc + 1 )) ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=$(( fail + 1 )) ; }

## Findings for the current fixture, one per line: '<rule msg>\x1f<loc>' or a
## NOTE. Asserted by rule tag plus the ':<line>'' location suffix.
output=""
run_det() {
   printf '%s\n' "$1" > "${test_dir}/subject.sh"
   output="$("${DET}" "${test_dir}/subject.sh" 2>/dev/null || true)"
}
## True if RULE is reported at LINE.
at_line() {
   grep --extended-regexp --quiet -- "${1}.*:${2}'" <<< "${output}"
}
assert_at() {
   if at_line "${2}" "${3}"; then note_pass "${1}"; else
      note_fail "${1} (expected ${2} at line ${3})"; printf '%s\n' "${output}" >&2; fi
}
assert_not_at() {
   if at_line "${2}" "${3}"; then
      note_fail "${1} (${2} wrongly at line ${3})"; printf '%s\n' "${output}" >&2
   else note_pass "${1}"; fi
}

## --- command position: data that only LOOKS like a command is spared ---------
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'rm -rf /a' \
   'sudo rm -rf /b' \
   'git rm cached' \
   'echo "rm -rf and apt-get in a string are data"' \
   'arr=(timeout 5 x)' \
   'cat <<EOF' \
   'rm -rf inside heredoc is data' \
   'EOF')"
assert_at     "R-120 flags a real rm"                 "R-120" 2
assert_at     "R-120 unwraps sudo rm"                 "R-120" 3
assert_not_at "R-120 spares 'git rm' (command=git)"   "R-120" 4
assert_not_at "R-120 spares rm inside a string"       "R-120" 5
assert_not_at "R-200 spares timeout in an array"      "R-200" 6
assert_not_at "R-120 spares rm inside a heredoc body" "R-120" 8
assert_at     "R-034 flags the echo command"          "R-034" 5

## --- ':' null command: statement vs loop condition --------------------------
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   ':' \
   ': > /truncate' \
   ': "${var:=default}"' \
   'while :; do break; done')"
assert_at     "R-130 flags a bare ':'"                "R-130" 2
assert_at     "R-130 flags ': > file' truncation"     "R-130" 3
assert_not_at "R-130 spares ': \${var:=default}'"     "R-130" 4
assert_not_at "R-130 spares the 'while :' condition"  "R-130" 5

## --- grep quiet: pipe-consuming vs short flag (pipe op derived, not magic) ---
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'seq 3 | grep -q x' \
   'grep -iq y file' \
   'grep --quiet -- pat file')"
assert_at     "R-161 flags a quiet grep consuming a pipe" "quiet grep consuming a pipe" 2
assert_at     "R-161 flags a short quiet flag"            "grep short quiet flag" 3
assert_not_at "R-161 spares a long quiet file read"       "R-161" 4

## --- R-103 exec: process replacement vs fd-redirect vs help text ------------
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'exec myprog --flag' \
   'exec 9>lock' \
   'exec [--workdir DIR] [--raw] -- CMD')"
assert_at     "R-103 flags process-replacement exec"     "R-103" 2
assert_not_at "R-103 spares an fd-redirection exec"      "R-103" 3
assert_not_at "R-103 spares 'exec [' help text"          "R-103" 4

## --- shfmt comment-tail-backslash quirk: hidden command still detected -------
## bs via ANSI-C quoting so THIS source carries no '\'-before-quote (SC1003).
bs=$'\\'
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   "true # note ${bs}" \
   'timeout 5 cmd')"
assert_at "R-200 sees a command hidden by a comment-tail backslash" "R-200" 3

## --- arg-taking option VALUES: skipped, never mistaken for a flag/operand -----
## (regression for ai-review findings: the shared option scanner must skip a
## value-taking option's separate value.)
g='grep'
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'sudo -u www-data rm -rf /x' \
   "${g} -e foo -q file" \
   "${g} -e -q pattern" \
   'python3 -W error -- tool.py' \
   'python3 -m coverage run -- harness.py')"
assert_at     "R-120 unwraps 'sudo -u VALUE rm' (value skipped)"     "R-120" 2
assert_at     "R-161 sees '-q' after 'grep -e foo' (value skipped)"  "grep short quiet flag" 3
assert_not_at "R-161 spares 'grep -e -q' (-q is -e's value)"         "R-161" 4
assert_at     "R-193 sees '--' after 'python -W error' (value skipped)" "R-193" 5
assert_not_at "R-193 spares 'python -m coverage run -- x.py'"        "R-193" 6

## --- expanded option values ('--mode=\"\$x\"') counted, not false-flagged -----
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'mkdir --mode="$m" "$TMPDIR/x"' \
   'timeout --kill-after="$k" 5 cmd')"
assert_not_at "R-172 spares an atomic --mode with an expanded value"  "R-172" 2
assert_not_at "R-200 spares --kill-after with an expanded value"      "R-200" 3

## --- R-130 spares no-op stubs + condition pipelines, keeps bare/redirect ------
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   ':' \
   'stub() { :; }' \
   'case "$x" in a) : ;; esac' \
   'while : | true; do break; done')"
assert_at     "R-130 flags a bare ':' alone on its line"             "R-130" 2
assert_not_at "R-130 spares a ':' no-op function stub"               "R-130" 3
assert_not_at "R-130 spares a ':' no-op case arm"                    "R-130" 4
assert_not_at "R-130 spares ':' in a condition pipeline"             "R-130" 5

## Self-test the FAIL gate: a forced failure must make the script exit non-zero.
if [ -n "${TEST_SELFCHECK_FAIL_GATE:-}" ]; then
   note_fail "self-test forced failure"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-detect: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-detect: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
