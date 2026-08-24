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

## run the detector over a specifically-NAMED file (config rules select by path).
run_det_at() {
   local f="${test_dir}/$1"
   mkdir --parents -- "$(dirname -- "${f}")"
   printf '%s\n' "$2" > "${f}"
   output="$("${DET}" "${f}" 2>/dev/null || true)"
}

## --- gate-BYPASS / gate-BLINDING regressions (ai-review findings) ------------
## sudo with an arg-taking option whose value is QUOTED: the unwrap must not
## abort on the None literal and miss the real command.
run_det "$(printf '%s\n' '#!/bin/bash' 'sudo FOO="bar" rm -rf /x' \
   'sudo -u www-data rm -rf /y')"
assert_at "R-120 sees rm past a quoted 'sudo FOO=\"bar\"' prefix" "R-120" 2
assert_at "R-120 sees rm past 'sudo -u www-data'"                "R-120" 3
## CRLF: a comment-tail backslash must still be neutralized so the next command
## is not swallowed (a '\r' left on the line would defeat the backslash strip).
printf '%b' '#!/bin/bash\r\n# c \\\r\nrm -rf /x\r\n' > "${test_dir}/crlf.sh"
output="$("${DET}" "${test_dir}/crlf.sh" 2>/dev/null || true)"
assert_at "R-120 not blinded by a CRLF comment-tail backslash" "R-120" 3

## --- config-hosted embedded shell: R-191/192/194/195/100 --------------------
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -c "a' 'b' 'c' 'd' 'e' 'f' 'g"')"
assert_at "R-192 flags a >5-line bash -c program" "R-192" 2

run_det_at "etc/systemd/system/x.service" \
   "$(printf '%s\n' '[Service]' 'ExecStart=/bin/bash -c "a; b; c"')"
assert_at "R-191 flags a multi-statement systemd Exec" "R-191" 2
run_det_at "etc/systemd/system/glue.service" \
   "$(printf '%s\n' '[Service]' 'ExecStart=/bin/echo done')"
assert_not_at "R-191 spares a single-command Exec" "R-191" 2

run_det_at "etc/apt/apt.conf.d/99x" \
   'DPkg::Post-Invoke {"if [ -x /x ]; then /x; fi"};'
assert_at "R-194 flags an if-block in an apt hook" "R-194" 1
run_det_at "etc/apt/apt.conf.d/98x" 'DPkg::Post-Invoke {"/usr/libexec/hook"};'
assert_not_at "R-194 spares a single-command apt hook" "R-194" 1

run_det_at "etc/cron.d/job" '0 3 * * * root cd /s && ./p.sh; systemctl restart a'
assert_at "R-195 flags a multi-statement cron command" "R-195" 1

run_det_at ".github/workflows/ci.yml" \
   "$(printf '%s\n' 'jobs:' '  x:' '    steps:' '      - run: |' \
      '          a' '          b' '          c' '          d' '          e' \
      '          f')"
assert_at "R-100 flags a >5-line workflow run block" "R-100" 4

## --- R-220 unauthorized skip -------------------------------------------------
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'type -P foo || exit 77' \
   'type -P bar || exit 77  ## style-ok: allow-skip: bar is an optional target' \
   '## style-ok: allow-skip: optional component' \
   '[ -x /opt/x ] || exit 77' \
   "printf 'the words exit 77 in a string are not a skip'" \
   'return 77')"
assert_at     "R-220 flags an unwaived 'exit 77'"              "R-220" 2
assert_not_at "R-220 spares an 'exit 77' with a trailing waiver" "R-220" 3
assert_not_at "R-220 spares an 'exit 77' waived on the line above" "R-220" 5
assert_not_at "R-220 spares 'exit 77' text inside a string"    "R-220" 6
assert_at     "R-220 flags an unwaived 'return 77'"            "R-220" 7
## A bare 'allow-skip' with no reason does NOT authorize the skip.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || exit 77  ## style-ok: allow-skip')"
assert_at "R-220 rejects a reasonless 'allow-skip'" "R-220" 2

## --- R-212 allow-downgrades: real argument vs quoted mention ----------------
## The legacy regex went false-NEGATIVE when any quote appeared earlier on the
## line; the AST reads --allow-downgrades as a real argument word regardless.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'printf "%s" "x"; apt-get-noninteractive install --allow-downgrades -- pkg' \
   'true "never use --allow-downgrades in prose"')"
assert_at     "R-212 flags --allow-downgrades after a quoted separator" "R-212" 2
assert_not_at "R-212 spares a quoted --allow-downgrades mention"        "R-212" 3

## --- R-213 lintian-disable: real assignment vs quoted prose / longer name ----
## The legacy regex went false-POSITIVE on quoted prose naming the flag and
## false-NEGATIVE on an assignment after a separator; the AST keys on a real
## 'make_use_lintian' Assign node valued 'false' (quoted or not).
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'make_use_lintian=false genmkfile deb-pkg' \
   'true; make_use_lintian=false genmkfile deb-pkg' \
   'make_use_lintian=false' \
   'make_use_lintian="false"' \
   'disable_make_use_lintian=false' \
   'make_use_lintian=true' \
   'true "make_use_lintian=false is forbidden"')"
assert_at     "R-213 flags an env-prefix assignment"           "R-213" 2
assert_at     "R-213 flags an assignment after a separator"    "R-213" 3
assert_at     "R-213 flags a standalone assignment"            "R-213" 4
assert_at     "R-213 flags a quoted 'false' value"             "R-213" 5
assert_not_at "R-213 spares a longer variable name"            "R-213" 6
assert_not_at "R-213 spares make_use_lintian=true"             "R-213" 7
assert_not_at "R-213 spares a quoted mention in a string"      "R-213" 8

## R-213 waiver silences it.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   '## style-ok: allow-lintian-disable' \
   'make_use_lintian=false genmkfile deb-pkg')"
assert_not_at "R-213 respects the allow-lintian-disable waiver" "R-213" 3

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
