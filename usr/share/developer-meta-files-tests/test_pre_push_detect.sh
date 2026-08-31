#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Truth-table test for 'dist-ai-style --detect', the parser-backed style detector
## (over the shfmt AST via dist_ai.rules). Drives the REAL shipped
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
DET="${tool_test_dir}/../../bin/dist-ai-style"
if [ ! -x "${DET}" ]; then
   DET='/usr/bin/dist-ai-style'
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
   local rc
   printf '%s\n' "$1" > "${test_dir}/subject.sh"
   output="$("${DET}" --detect "${test_dir}/subject.sh" 2>/dev/null)" && rc=0 || rc=$?
   ## dist-ai-style exits 3 on an INTERNAL crash (distinct from 0 clean / 1 findings).
   ## The old '|| true' swallowed it, flattening `output` to empty so every
   ## assert_not_at below read as a spurious PASS -- a fabricated green. Fail LOUD.
   if [ "${rc}" -eq 3 ]; then
      printf '%s\n' "FATAL: dist-ai-style --detect crashed (exit 3) on the fixture" >&2
      exit 1
   fi
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
   output="$("${DET}" --detect "${f}" 2>/dev/null || true)"
}

## --- gate-BYPASS / gate-BLINDING regressions (ai-review findings) ------------
## sudo with an arg-taking option whose value is QUOTED: the unwrap must not
## abort on the None literal and miss the real command.
run_det "$(printf '%s\n' '#!/bin/bash' 'sudo FOO="bar" rm -rf /x' \
   'sudo -u www-data rm -rf /y')"
assert_at "R-120 sees rm past a quoted 'sudo FOO=\"bar\"' prefix" "R-120" 2
assert_at "R-120 sees rm past 'sudo -u www-data'"                "R-120" 3
## STACKED wrapper: 'sudo sudo rm' / 'sudo doas rm' must peel EVERY leading wrapper,
## not just one, or effective_command resolves to 'sudo'/'doas' and the whole class it
## backs (R-120 safe-rm, R-034 echo, R-210/R-211 apt/dpkg) is bypassed. Fixed at root
## in the shared unwrap, so one R-120 + one R-034 case proves the class.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'sudo sudo rm -rf /x' \
   'sudo doas rm -rf /y' \
   'sudo sudo echo hi')"
assert_at "R-120 unwraps a stacked 'sudo sudo rm'"   "R-120" 2
assert_at "R-120 unwraps a stacked 'sudo doas rm'"   "R-120" 3
assert_at "R-034 unwraps a stacked 'sudo sudo echo'" "R-034" 4
## ... and the INNER wrapper's own flags/'--' must be skipped too: command_tokens flattens
## everything past the first operand, so the unwrap RE-PARSES each layer or a flag ('-u') would
## surface as the command and still bypass. (ai-review agy/grok.)
run_det "$(printf '%s\n' '#!/bin/bash' \
   'sudo sudo -u root rm -rf /x' \
   'sudo doas -u root rm -rf /y' \
   'sudo sudo -- rm -rf /z' \
   'sudo sudo -n apt-get update')"
assert_at "R-120 unwraps 'sudo sudo -u root rm' (inner flag+value)" "R-120" 2
assert_at "R-120 unwraps 'sudo doas -u root rm'"                    "R-120" 3
assert_at "R-120 unwraps 'sudo sudo -- rm' (inner end-of-options)"  "R-120" 4
assert_at "R-210 unwraps 'sudo sudo -n apt-get'"                    "R-210" 5
## A maliciously DEEP wrapper chain must not crash the linter: the unwrap is ITERATIVE,
## not recursive, so it peels any depth without a RecursionError. (ai-review agy.)
deep_sudo="$(printf 'sudo %.0s' $(seq 1 1500))"
run_det "$(printf '%s\n' '#!/bin/bash' "${deep_sudo}rm -rf /x")"
assert_at "R-120 unwraps a 1500-deep 'sudo ... rm' without crashing" "R-120" 2
## A QUOTED or BACKSLASH-ESCAPED command word resolves via word_string to the value bash
## actually runs, so quoting/escaping no longer bypasses the command scan: 'sudo "rm"', a
## bare '"rm"', '\rm', and 'sudo \rm' all still flag R-120. (ai-review claude.)
run_det "$(printf '%s\n' '#!/bin/bash' \
   'sudo "rm" -rf /x' \
   '"rm" -rf /y' \
   '\rm -rf /z' \
   'sudo \rm -rf /w')"
assert_at "R-120 catches a quoted command 'sudo \"rm\"'" "R-120" 2
assert_at "R-120 catches a bare quoted '\"rm\"'"         "R-120" 3
assert_at "R-120 catches a backslash-escaped '\\rm'"     "R-120" 4
assert_at "R-120 catches 'sudo \\rm'"                    "R-120" 5
## CRLF: a comment-tail backslash must still be neutralized so the next command
## is not swallowed (a '\r' left on the line would defeat the backslash strip).
printf '%b' '#!/bin/bash\r\n# c \\\r\nrm -rf /x\r\n' > "${test_dir}/crlf.sh"
output="$("${DET}" --detect "${test_dir}/crlf.sh" 2>/dev/null || true)"
assert_at "R-120 not blinded by a CRLF comment-tail backslash" "R-120" 3

## --- config-hosted embedded shell: R-191/192/194/195/100 --------------------
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -c "a' 'b' 'c' 'd' 'e' 'f' 'g"')"
assert_at "R-192 flags a >5-line bash -c program" "R-192" 2
## Wrapped: a shell '-c' reached THROUGH a wrapper ('ssh host -- bash -lc PROG')
## is still an inline program -- the exact shape that slipped the gate once.
run_det "$(printf '%s\n' '#!/bin/bash' 'ssh host -- bash -lc "a' 'b' 'c' 'd' 'e' 'f' 'g"')"
assert_at "R-192 flags a wrapped 'ssh -- bash -lc' program" "R-192" 2
## But NOT 'echo bash -c ...' -- echo is not a wrapper, so the bash token is
## data, not the effective command (the documented false-positive to avoid).
run_det "$(printf '%s\n' '#!/bin/bash' 'echo bash -c "a' 'b' 'c' 'd' 'e' 'f' 'g"')"
assert_not_at "R-192 spares 'echo bash -c' (echo is not a wrapper)" "R-192" 2

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
## apt.conf's brace block is newline-insensitive: the directive and its quoted
## value need not share a line. A multi-line block form must NOT bypass R-194.
## Canary: the per-line scan missed this entirely.
run_det_at "etc/apt/apt.conf.d/97x" \
   "$(printf '%s\n' 'DPkg::Post-Invoke' '{' '   "a; b";' '};')"
assert_at "R-194 flags a multi-line block apt hook" "R-194" 1
run_det_at "etc/apt/apt.conf.d/96x" \
   "$(printf '%s\n' 'DPkg::Post-Invoke' '{' '   "/usr/libexec/hook";' '};')"
assert_not_at "R-194 spares a multi-line single-command apt hook" "R-194" 1

run_det_at "etc/cron.d/job" '0 3 * * * root cd /s && ./p.sh; systemctl restart a'
assert_at "R-195 flags a multi-statement cron command" "R-195" 1

run_det_at ".github/workflows/ci.yml" \
   "$(printf '%s\n' 'jobs:' '  x:' '    steps:' '      - run: |' \
      '          a' '          b' '          c' '          d' '          e' \
      '          f')"
assert_at "R-100 flags a 6-statement workflow run block" "R-100" 4

## A single command wrapped over 6 backslash-continued lines is ONE statement,
## not a block -- the old line count wrongly flagged it (canary for that fix).
run_det_at ".github/workflows/cont.yml" \
   "$(printf '%s\n' 'jobs:' '  x:' '    steps:' '      - run: |' \
      "          cppcheck \\" "            --a \\" "            --b \\" \
      "            --c \\" "            --d \\" '            --e')"
assert_not_at "R-100 spares a single backslash-continued command" "R-100" 4

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

## --- quote-aware loopholes (ai-review): a quoted arg is the same command -----
## R-220: 'exit "77"' is the same skip as 'exit 77'.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit "77"')"
assert_at "R-220 flags a quoted 'exit \"77\"'" "R-220" 2
## Bash parses the code with strtol -- leading whitespace skipped, trailing
## tolerated -- so 'exit "  77  "' really exits 77 (verified), the SAME skip. A
## fullmatch on the unstripped quoted word missed the padded form (a silent pass).
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit "  77  "')"
assert_at "R-220 flags a whitespace-padded 'exit \"  77  \"'" "R-220" 2
## R-220: bash parses the arg as DECIMAL, so 'exit 077' runs as 77 (not octal 63)
## -- the SAME unwaived skip, must be flagged. A leading-zero '== 77' string check
## missed it.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit 077')"
assert_at "R-220 flags 'exit 077' (decimal 77)" "R-220" 2
## Non-77 codes must be spared -- normalize the VALUE, do not substring-match '77'.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit 770' 'bar || return 78')"
assert_not_at "R-220 spares 'exit 770'"   "R-220" 2
assert_not_at "R-220 spares 'return 78'"  "R-220" 3
## bash truncates the exit code to 8 bits, so ANY code == 77 mod 256 runs as 77 at
## runtime ('exit 333' -> 77, 'exit -179' -> 77) and must be gated; a code that mods
## to something else is spared. A literal '== 77' missed the whole truncation class.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit 333' 'bar || exit -179')"
assert_at "R-220 flags 'exit 333' (333 mod 256 = 77)"  "R-220" 2
assert_at "R-220 flags 'exit -179' (-179 mod 256 = 77)" "R-220" 3
## A CONSTANT '$(( ))' code is statically evaluable and runs as a fixed value, so a
## skip disguised as arithmetic ('exit $((70+7))' -> 77) must be flagged; a DYNAMIC
## '$((rc+1))' has no static value and is spared (decline-rather-than-guess), and a
## constant that mods to non-77 is spared too. A word_string-only check missed all of
## these -- an ArithmExp has no literal value.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || exit $((70+7))' \
   'bar || exit $((154/2))' \
   'baz || exit $((rc + 1))' \
   'qux || exit $((70+6))')"
assert_at     "R-220 flags 'exit \$((70+7))' (constant 77)"    "R-220" 2
assert_at     "R-220 flags 'exit \$((154/2))' (constant 77)"   "R-220" 3
assert_not_at "R-220 spares dynamic 'exit \$((rc + 1))'"       "R-220" 4
assert_not_at "R-220 spares constant non-77 'exit \$((70+6))'" "R-220" 5
## A HUGE constant must evaluate with INTEGER arithmetic, never float: 'a/b' via float
## OverflowErrors past ~1e308 (crashing the linter on untrusted data) and loses precision
## above 2**53. '77 * BIG / BIG' is 77 for any BIG -> must still flag, and must not crash.
## (ai-review agy/grok.)
arith_big="$(printf '9%.0s' $(seq 1 400))"
run_det "$(printf '%s\n' '#!/bin/bash' \
   "foo || exit \$(( 77 * ${arith_big} / ${arith_big} ))")"
assert_at "R-220 evaluates a huge constant with integer arithmetic (no float overflow)" "R-220" 2
## A leading-zero (bash octal) literal cannot be mapped to a value without a full bash
## arithmetic parser, so it DECLINES -- a miss, never a crash or a decimal misread.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit $((0115))')"
assert_not_at "R-220 declines a bash-octal '\$((0115))' (not misread as decimal)" "R-220" 2
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit 333' 'bar || exit 300')"
assert_not_at "R-220 spares 'exit 300' (300 mod 256 = 44)" "R-220" 3
## exec-wrapper spellings: bash runs the SAME exit/return builtin through '\exit',
## 'builtin exit' and 'command exit', so a skip must not evade the gate by an
## alternate spelling (sibling apt/dpkg rules unwrap sudo/doas the same way).
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || builtin exit 77' \
   'bar || command exit 77' \
   'baz || \exit 77' \
   'qux || builtin return 77')"
assert_at "R-220 flags a wrapped 'builtin exit 77'"    "R-220" 2
assert_at "R-220 flags a wrapped 'command exit 77'"    "R-220" 3
assert_at "R-220 flags a backslash '\\exit 77'"        "R-220" 4
assert_at "R-220 flags a wrapped 'builtin return 77'"  "R-220" 5
## wrapper OPTIONS and '--', a quoted name, and 'exit --' all still run exit 77 in
## bash (verified) and must flag; 'command -v/-V' only DESCRIBES and is spared.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || command -p exit 77' \
   'bar || command -- exit 77' \
   'baz || builtin -- exit 77' \
   'qux || exit -- 77' \
   'zap || "exit" 77')"
assert_at "R-220 flags 'command -p exit 77'"   "R-220" 2
assert_at "R-220 flags 'command -- exit 77'"   "R-220" 3
assert_at "R-220 flags 'builtin -- exit 77'"   "R-220" 4
assert_at "R-220 flags 'exit -- 77'"           "R-220" 5
assert_at "R-220 flags a quoted \"exit\" 77"   "R-220" 6
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || command -v exit 77')"
assert_not_at "R-220 spares 'command -v exit 77' (describes, does not run)" "R-220" 2
## wrapper INVALID options: bash rejects 'builtin -p' (builtin takes NO options) and
## 'command -x' (unknown option) BEFORE exit runs (verified: both print 'continued'),
## so neither is a real skip -- R-220 must not flag them as an unauthorized exit 77.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || builtin -p exit 77' \
   'bar || command -x exit 77')"
assert_not_at "R-220 spares 'builtin -p exit 77' (bash rejects -p, exit never runs)" "R-220" 2
assert_not_at "R-220 spares 'command -x exit 77' (bash rejects -x, exit never runs)" "R-220" 3
## NESTED wrappers: bash runs 'command builtin exit 77' (and 'builtin command ...')
## through BOTH layers, so a skip must not evade R-220 by double-wrapping. Unwrap
## must loop, not stop after one layer.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || command builtin exit 77' \
   'bar || builtin command return 77' \
   'baz || command -p builtin exit 77')"
assert_at "R-220 flags a NESTED 'command builtin exit 77'"       "R-220" 2
assert_at "R-220 flags a NESTED 'builtin command return 77'"     "R-220" 3
assert_at "R-220 flags a nested wrap with options 'command -p builtin exit 77'" "R-220" 4
## the waiver is still honored THROUGH the wrapper, and a wrapped non-77 is spared.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || builtin exit 77  ## style-ok: allow-skip: optional target' \
   'bar || command exit 78')"
assert_not_at "R-220 waiver honored through 'builtin exit'"     "R-220" 2
assert_not_at "R-220 spares a wrapped non-77 'command exit 78'" "R-220" 3
## waiver-spoof: the 'allow-skip' waiver must be a REAL comment, never a
## '## style-ok: allow-skip:' string inside a quoted value or a bare variable
## assignment -- else an unwaived skip goes green (the fabricated-pass R-220 closes).
run_det "$(printf '%s\n' '#!/bin/bash' \
   'echo "## style-ok: allow-skip: fake" && exit 77')"
assert_at "R-220 flags a skip with a decoy waiver inside a string" "R-220" 2
run_det "$(printf '%s\n' '#!/bin/bash' \
   'z="## style-ok: allow-skip: nice try"' \
   'foo || exit 77')"
assert_at "R-220 flags a skip after a decoy-waiver var assignment" "R-220" 3
## a REAL comment waiver (own line above) still authorizes the skip.
run_det "$(printf '%s\n' '#!/bin/bash' \
   '## style-ok: allow-skip: optional target' \
   'foo || exit 77')"
assert_not_at "R-220 honors a real comment waiver on the line above" "R-220" 3
## coexisting-comment spoof: a decoy '## style-ok: allow-skip:' string must NOT
## waive just because an UNRELATED real comment shares the line -- the waiver is
## the comment's OWN text, anchored at its start, not anything on the raw line.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'echo "## style-ok: allow-skip: fake" && exit 77  # note')"
assert_at "R-220 flags a decoy-string skip beside an unrelated comment" "R-220" 2
## a REAL trailing waiver on the skip's own line still authorizes it.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'foo || exit 77  ## style-ok: allow-skip: real reason')"
assert_not_at "R-220 honors a real trailing comment waiver" "R-220" 2
## '+77' runs as 77 in bash, so 'exit +77' is a skip and must be gated.
run_det "$(printf '%s\n' '#!/bin/bash' 'foo || exit +77')"
assert_at "R-220 flags 'exit +77' (runs as 77)" "R-220" 2
## R-090: '-pv' / '-p -v' clusters are still 'command -v'.
run_det "$(printf '%s\n' '#!/bin/bash' 'command -pv foo' 'command -p -v bar')"
assert_at "R-090 flags a 'command -pv' cluster"   "R-090" 2
assert_at "R-090 flags a 'command -p -v' split"   "R-090" 3
## R-102: an option before the script ('bash -x build.sh') still prepends an
## interpreter; a '-c' program does NOT (that is R-192's inline-program case).
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -x ci/build.sh' 'bash -c "echo hi"')"
assert_at     "R-102 flags 'bash -x <script>'"       "R-102" 2
assert_not_at "R-102 spares 'bash -c <program>'"     "R-102" 3
## R-211 (advisory): a quoted state action is still state-changing.
run_det "$(printf '%s\n' '#!/bin/bash' 'dpkg "--install" pkg.deb')"
assert_at "R-211 flags a quoted 'dpkg \"--install\"'" "R-211" 2

## --- comment-strip loopholes (ai-review): a '${var#pat}' '#' is NOT a comment
## R-170: a hardcoded temp path AFTER a '${var#pat}' on the same line still
## flags (the old '^[^#]*' skip stopped at the expansion's '#' and missed it).
## Assemble the literal so it does not appear in THIS tracked file, which the
## gate also scans (like the ';;' assembly elsewhere).
st='/t'; st="${st}mp"
run_det "$(printf '%s\n' '#!/bin/bash' "x=\"\${d#/y}\"; cp -- foo.dat ${st}")"
assert_at "R-170 sees a hardcoded temp path past a '\${var#pat}'" "R-170" 2
## R-010: a was_executed guard AFTER a '${var#pat}' is still recognized, so the
## source-able guarded script stays exempt (no spurious strict-mode failure).
run_det "$(printf '%s\n' '#!/bin/bash' 'x="${d#/y}"; was_executed "$0" -- main "$@"')"
assert_not_at "R-010 recognizes a guard past a '\${var#pat}'" "R-010" 1

## --- option-parse edges (ai-review round 2) ---------------------------------
## R-090: '--' ends options, so 'command -- -v' RUNS -v, it is not describe mode.
run_det "$(printf '%s\n' '#!/bin/bash' 'command -- -v foo')"
assert_not_at "R-090 spares 'command -- -v' (-- ends options)" "R-090" 2
## R-102: an option that TAKES A VALUE ('-o errexit') and '--' before the script
## must still reach the script; '-s' (stdin) and '-c' (program) must not.
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -o errexit ci/build.sh')"
assert_at "R-102 flags 'bash -o VALUE <script>'" "R-102" 2
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -- ci/build.sh')"
assert_at "R-102 flags 'bash -- <script>'" "R-102" 2
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -s -- arg')"
assert_not_at "R-102 spares 'bash -s' (script from stdin)" "R-102" 2
## a BUNDLED cluster whose LAST char is the value-taking '-o'/'-O' ('-eo pipefail')
## still consumes the NEXT word as its value, so the script after it must be reached.
## A bare 'cluster in (o,O)' check missed the bundled form and read 'pipefail' as the
## script, silently sparing 'bash -eo pipefail <script>'.
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -eo pipefail ci/build.sh')"
assert_at "R-102 flags a bundled 'bash -eo VALUE <script>'" "R-102" 2
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -Eeo pipefail ci/build.sh')"
assert_at "R-102 flags a bundled 'bash -Eeo VALUE <script>'" "R-102" 2
## but an ATTACHED value ('-oe' == -o with value 'e') does NOT take the next word.
run_det "$(printf '%s\n' '#!/bin/bash' 'bash -oe ci/build.sh')"
assert_at "R-102 flags 'bash -oe <script>' (attached -o value, script still reached)" "R-102" 2

## --- path-qualified / global-option command resolution (ai-review round 3) ---
## R-120: '/bin/rm' and '/usr/bin/sudo rm' are the same programs (basename).
run_det "$(printf '%s\n' '#!/bin/bash' '/bin/rm -rf /x')"
assert_at "R-120 flags a path-qualified '/bin/rm'" "R-120" 2
run_det "$(printf '%s\n' '#!/bin/bash' '/usr/bin/sudo rm -rf /x')"
assert_at "R-120 flags rm behind a path-qualified sudo" "R-120" 2
## R-062: a git GLOBAL option before the subcommand ('git -C dir check-ref-format')
## must not shift the subcommand out of view.
run_det "$(printf '%s\n' '#!/bin/bash' 'git -C /some/repo check-ref-format -- "$b"')"
assert_at "R-062 flags 'git -C dir check-ref-format --'" "R-062" 2

## --- R-212 allow-downgrades: real argument vs quoted mention ----------------
## The legacy regex went false-NEGATIVE when any quote appeared earlier on the
## line; the AST reads --allow-downgrades as a real argument word regardless.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'printf "%s" "x"; apt-get-noninteractive install --allow-downgrades -- pkg' \
   'true "never use --allow-downgrades in prose"' \
   'apt-get-noninteractive install "--allow-downgrades" -- pkg')"
assert_at     "R-212 flags --allow-downgrades after a quoted separator" "R-212" 2
assert_not_at "R-212 spares a quoted --allow-downgrades mention"        "R-212" 3
## A fully-QUOTED flag word still passes the flag to apt-get; word_lit declined
## it (false-negative), word_string catches it. Canary for that fix.
assert_at     "R-212 flags a fully-quoted --allow-downgrades flag word" "R-212" 4
## The ENABLING forms are forbidden -- the bare flag, or '=<truthy>' (apt truthy
## tokens true/yes/on/1/with/enable, case-insensitive).
run_det "$(printf '%s\n' '#!/bin/bash' \
   'apt-get-noninteractive install --allow-downgrades=true -- pkg')"
assert_at "R-212 flags '--allow-downgrades=true'" "R-212" 2
run_det "$(printf '%s\n' '#!/bin/bash' \
   'apt-get-noninteractive install --allow-downgrades=yes -- pkg')"
assert_at "R-212 flags '--allow-downgrades=yes'" "R-212" 2
## The DISABLING forms ('=false'/'=0'/...) read FALSE in apt -- a no-op, not the
## risk this rule guards -- so they must be SPARED, not flagged.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'apt-get-noninteractive install --allow-downgrades=false -- pkg')"
assert_not_at "R-212 spares '--allow-downgrades=false' (disabling no-op)" "R-212" 2
run_det "$(printf '%s\n' '#!/bin/bash' \
   'apt-get-noninteractive install --allow-downgrades=0 -- pkg')"
assert_not_at "R-212 spares '--allow-downgrades=0' (disabling)" "R-212" 2
## A longer flag that merely PREFIXES the name (no '=') is a different flag -- spare it.
run_det "$(printf '%s\n' '#!/bin/bash' \
   'apt-get-noninteractive install --allow-downgrades-foo -- pkg')"
assert_not_at "R-212 spares '--allow-downgrades-foo' (not the flag)" "R-212" 2

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

## 'export'/'declare make_use_lintian=false' is a DeclClause, not a CallExpr
## Assign -- the rule must scan both. Canary: FAILs on CallExpr-only detection.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'export make_use_lintian=false' \
   'declare make_use_lintian=false')"
assert_at "R-213 flags 'export make_use_lintian=false' (DeclClause)" "R-213" 2
assert_at "R-213 flags 'declare make_use_lintian=false' (DeclClause)" "R-213" 3

## R-213 waiver silences it.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   '## style-ok: allow-lintian-disable' \
   'make_use_lintian=false genmkfile deb-pkg')"
assert_not_at "R-213 respects the allow-lintian-disable waiver" "R-213" 3

## --- R-063 printf -v injection guard ----------------------------------------
## A dynamic '-v' target evaluates an array subscript ('name[$(cmd)]' RUNS cmd),
## so it must be guarded by check_variable_name on the SAME name, earlier in the
## SAME function. Line numbers assert both the match and the scope/ordering.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'guarded() {' \
   '  check_variable_name "${n}" || return 1' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'unguarded() {' \
   '  printf -v "${m}" "%s" "y"' \
   '}' \
   'literal() {' \
   '  printf -v out "%s" "z"' \
   '}')"
assert_not_at "R-063 spares a guarded dynamic printf -v"        "R-063" 4
assert_at     "R-063 flags an unguarded dynamic printf -v"      "R-063" 7
assert_not_at "R-063 spares a literal (static) target"          "R-063" 10

## Scope + ordering + matching: a guard AFTER the printf, a guard for a DIFFERENT
## variable, a guard in a SIBLING function, and a command-substitution name all
## leave the printf UNGUARDED.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'after() {' \
   '  printf -v "${a}" "%s" "x"' \
   '  check_variable_name "${a}" || return 1' \
   '}' \
   'wrongvar() {' \
   '  check_variable_name "${good}" || return 1' \
   '  printf -v "${bad}" "%s" "x"' \
   '}' \
   'cmdsub() {' \
   '  printf -v "$(build_name)" "%s" "x"' \
   '}' \
   'sibling_guard() {' \
   '  check_variable_name "${v}" || return 1' \
   '}' \
   'sibling_use() {' \
   '  printf -v "${v}" "%s" "x"' \
   '}')"
assert_at "R-063 flags a guard placed AFTER the printf"         "R-063" 3
assert_at "R-063 flags a guard naming a different variable"     "R-063" 8
assert_at "R-063 flags a command-substitution target name"      "R-063" 11
assert_at "R-063 flags a guard confined to a sibling function"  "R-063" 17
## A guard whose result does NOT gate control flow must not silence R-063: a bare call
## (status discarded), one in a dead 'if false' branch, in a command substitution (only
## stdout captured), and in a subshell (its 'return' exits only the subshell). Only a
## recognized ENFORCING form ('check ... || <exit-like>') whose branch reaches the printf
## counts. (ai-review reviewdrain16.)
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'bare() {' \
   '  check_variable_name "${n}"' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'deadbranch() {' \
   '  if false; then check_variable_name "${n}" || return 1; fi' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'cmdsub_guard() {' \
   '  unused="$(check_variable_name "${n}")"' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'subshell_guard() {' \
   '  ( check_variable_name "${n}" || return 1 )' \
   '  printf -v "${n}" "%s" "x"' \
   '}')"
assert_at "R-063 flags a bare (status-discarded) guard"            "R-063" 4
assert_at "R-063 flags a guard in a dead 'if false' branch"        "R-063" 8
assert_at "R-063 flags a guard captured in a command substitution" "R-063" 12
assert_at "R-063 flags a guard confined to a subshell"             "R-063" 16
## More decoys whose guard does NOT actually gate the printf (ai-review reviewdrain16 re-gate):
## a '{...}' handler that never exits; a NEGATED '! check'; a guard inside a command
## substitution WITH '||'; a guard confined to an elif branch. (grok/claude.)
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'blocknoexit() {' \
   '  check_variable_name "${n}" || { true; }' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'negated() {' \
   '  ! check_variable_name "${n}" || return 1' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'cmdsub_or() {' \
   '  unused="$(check_variable_name "${n}" || return 1)"' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'elifbranch() {' \
   '  if false; then :; elif false; then :; else check_variable_name "${n}" || return 1; fi' \
   '  printf -v "${n}" "%s" "x"' \
   '}')"
assert_at "R-063 flags a '{...}' handler that never exits"          "R-063" 4
assert_at "R-063 flags a negated '! check' guard"                   "R-063" 8
assert_at "R-063 flags a guard in a command substitution with ||"   "R-063" 12
assert_at "R-063 flags a guard confined to an elif-chain else"      "R-063" 16
## A TOP-LEVEL 'check || return' cannot return (errors + falls through) -> not a guard.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'check_variable_name "${n}" || return 1' \
   'printf -v "${n}" "%s" "x"')"
assert_at "R-063 flags a top-level guard whose return cannot return" "R-063" 3
## ... but the LEGIT enforcing forms are still SPARED: a '{...}' handler whose last stmt
## exits, and a '|| continue' guard inside a loop (continue does gate there).
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'blockexits() {' \
   '  check_variable_name "${n}" || { echo bad >&2; return 1; }' \
   '  printf -v "${n}" "%s" "x"' \
   '}' \
   'loopguard() {' \
   '  for n in a b; do' \
   '    check_variable_name "${n}" || continue' \
   '    printf -v "${n}" "%s" "x"' \
   '  done' \
   '}')"
assert_not_at "R-063 spares a '{...}' handler whose last stmt returns" "R-063" 4
assert_not_at "R-063 spares a '|| continue' guard inside its loop"     "R-063" 9
## Class-killer: byte-span containment != execution reachability. A guard reaches a printf ONLY
## within one execution region -- a later function body, and any subshell/subst, are boundaries.
## (ai-review reviewdrain16 round 3.)
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'check_variable_name "${t}" || exit 1' \
   'dispatch() {' \
   '  printf -v "${t}" "%s" "x"' \
   '}' \
   'looptrap() {' \
   '  for k in a b; do' \
   '    ( check_variable_name "${k}" || continue; printf -v "${k}" "%s" "y" )' \
   '  done' \
   '}' \
   'subsplit() {' \
   '  ( check_variable_name "${v}" || return 1 )' \
   '  printf -v "${v}" "%s" "z"' \
   '}')"
assert_at "R-063 flags a top-level exit-guard vs a printf in a later function" "R-063" 4
assert_at "R-063 flags a printf whose ||continue guard is trapped in a subshell" "R-063" 8
assert_at "R-063 flags a printf after a guard confined to a subshell (||return)" "R-063" 13
## ... but the same-REGION good forms are SPARED: a guard + printf INSIDE one subshell (return
## exits the subshell before the printf runs), and a plain ||continue guard directly in the loop.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'samesubshell() {' \
   '  ( check_variable_name "${v}" || return 1; printf -v "${v}" "%s" "z" )' \
   '}' \
   'loopok() {' \
   '  for k in a b; do' \
   '    check_variable_name "${k}" || continue' \
   '    printf -v "${k}" "%s" "y"' \
   '  done' \
   '}')"
assert_not_at "R-063 spares a guard + printf inside the SAME subshell"     "R-063" 3
assert_not_at "R-063 spares a plain ||continue guard directly in the loop" "R-063" 8

## The ATTACHED spelling 'printf -vNAME' is analyzed too: a literal name is
## spared, an expanded one is guarded like the separate form.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'attached_literal() {' \
   '  printf -vout "%s" "z"' \
   '}' \
   'attached_dynamic() {' \
   '  printf -v"${d}" "%s" "z"' \
   '}')"
assert_not_at "R-063 spares an attached literal '-vout'"        "R-063" 3
assert_at     "R-063 flags an attached dynamic '-v\${d}'"       "R-063" 6

## bash printf option parsing: the FORMAT operand and '--' both END option
## scanning, so a '-v' after either is DATA, not a target (no false positive).
## Multiple '-v' -> bash writes the LAST, so that target is the one analyzed.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'printf "%s" -v "${notatarget}"' \
   'printf -- -v "${alsonot}"' \
   'printf -v safe -v "${last}" "%s" x')"
assert_not_at "R-063 spares a '-v' after the format operand (data)"  "R-063" 2
assert_not_at "R-063 spares a '-v' after '--' (data)"                "R-063" 3
assert_at     "R-063 analyzes the LAST '-v' target (bash uses it)"   "R-063" 4

## Quote removal happens before printf's getopt, so a QUOTED '-v' (separate or
## attached) is still the option -- a raw-text check would miss these.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'printf "-v" "${qsep}" "%s" x' \
   'printf "-v${qatt}" "%s" x' \
   'printf "%s" "-v" "${notopt}"')"
assert_at     "R-063 flags a quoted separate '\"-v\"' target"    "R-063" 2
assert_at     "R-063 flags a quoted attached '\"-v\${x}\"'"      "R-063" 3
assert_not_at "R-063 spares a quoted '-v' that is DATA"          "R-063" 4

## A name built from several expansions is guarded only if EVERY component was
## checked (bash evaluates the whole subscript); one covered component is not
## enough. And a guard in a NESTED function does not count for an outer printf.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'partial() {' \
   '  check_variable_name "${a}" || return 1' \
   '  printf -v "${a}${b}" "%s" x' \
   '}' \
   'complete() {' \
   '  check_variable_name "${c}" || return 1' \
   '  check_variable_name "${d}" || return 1' \
   '  printf -v "${c}${d}" "%s" x' \
   '}' \
   'nested() {' \
   '  helper() { check_variable_name "${n}" || return 1; }' \
   '  printf -v "${n}" "%s" x' \
   '}')"
assert_at     "R-063 flags a multi-component name with one component unchecked" "R-063" 4
assert_not_at "R-063 spares a multi-component name with every component checked" "R-063" 9
assert_at     "R-063 flags a guard confined to a NESTED function"               "R-063" 13

## A top-level guard before a top-level printf -v counts (scope starts at 0).
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'check_variable_name "${t}" || exit 1' \
   'printf -v "${t}" "%s" "x"')"
assert_not_at "R-063 spares a top-level guard before the printf" "R-063" 3

## The script-wide waiver silences the rule.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   '## style-ok: allow-unchecked-printf-v' \
   'printf -v "${n}" "%s" "x"')"
assert_not_at "R-063 respects the allow-unchecked-printf-v waiver" "R-063" 3

## R-063 sees an ESCAPED '-v' option: '\-v' is '-v' after bash unquoted escape
## removal, so the option scan must de-escape it -- else a dynamic target hidden
## behind '\-v' bypasses the injection guard. Canary: FAILS on the pre-de-escape
## detector, which read the shfmt Lit '\-v' verbatim and stopped option scanning.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'unguarded() {' \
   '  printf \-v "${m}" "%s" "y"' \
   '}')"
assert_at "R-063 flags an escaped \\-v printf target (de-escaped to -v)" "R-063" 3

## A command substitution in the target NAME is never made safe by a guard
## (bash runs it evaluating the array subscript), so a name mixing a CHECKED
## param with a '$(...)' must still flag. Canary: FAILs on param-coverage-only.
run_det "$(printf '%s\n' \
   '#!/bin/bash' \
   'f() {' \
   '  check_variable_name v || return 1' \
   '  printf -v "a[$v$(id)]" "%s" x' \
   '}')"
assert_at "R-063 flags a checked-param + command-substitution target" "R-063" 4

## --- text floor over --detect: R-001 non-ASCII, incl. a non-UTF-8 file --------
## The --detect front now owns the file R-001 floor (include_text), reported off
## the RAW bytes so a stray non-ASCII byte is caught even where the file is not
## valid UTF-8 -- matching the byte-level grep the bash gate used. Canary: FAILED
## when detect read decoded source only (an undecodable file gave source=None and
## no finding). 0xFF is never a valid UTF-8 byte.
printf '%b' '#!/bin/bash\ntrue \377\n' > "${test_dir}/badutf8.sh"
output="$("${DET}" --detect "${test_dir}/badutf8.sh" 2>/dev/null || true)"
if grep --quiet --fixed-strings -- 'R-001' <<< "${output}"; then
   note_pass "R-001 flags a non-ASCII byte in a non-UTF-8 file"
else
   note_fail "R-001 missed a non-ASCII byte in a non-UTF-8 file"
   printf '%s\n' "${output}" >&2
fi

## --- commit-message R-001 via --message-file --------------------------------
## The pending commit message is not a tree file; --message-file hands it to the
## SAME non-ASCII rule. A U+00E9 (0xC3 0xA9) in the body must be flagged; a clean
## ASCII message must pass.
printf '%b' 'subject line\n\nbody with \303\251 accent\n' > "${test_dir}/msg-bad"
output="$("${DET}" --detect --message-file "${test_dir}/msg-bad" 2>/dev/null || true)"
if grep --quiet --fixed-strings -- 'R-001' <<< "${output}"; then
   note_pass "R-001 flags a non-ASCII commit message via --message-file"
else
   note_fail "R-001 missed a non-ASCII commit message via --message-file"
   printf '%s\n' "${output}" >&2
fi
printf '%s\n' 'clean ascii subject' > "${test_dir}/msg-ok"
output="$("${DET}" --detect --message-file "${test_dir}/msg-ok" 2>/dev/null || true)"
if grep --quiet --fixed-strings -- 'R-001' <<< "${output}"; then
   note_fail "R-001 wrongly flagged a clean ASCII commit message"
   printf '%s\n' "${output}" >&2
else
   note_pass "R-001 spares a clean ASCII commit message"
fi
## A file waiver ('## style-ok: allow-non-ascii') that happens to appear in the
## MESSAGE must NOT suppress R-001 there -- a message is not a file. Canary: the
## message context decoded source, so has_waiver honored the in-message waiver
## and dropped the finding.
printf '%b' 'subj\n\n## style-ok: allow-non-ascii\nbody caf\303\251\n' \
   > "${test_dir}/msg-waiver"
output="$("${DET}" --detect --message-file "${test_dir}/msg-waiver" 2>/dev/null || true)"
if grep --quiet --fixed-strings -- 'R-001' <<< "${output}"; then
   note_pass "commit-message R-001 ignores an in-message allow-non-ascii waiver"
else
   note_fail "an in-message allow-non-ascii waiver suppressed commit-message R-001"
   printf '%s\n' "${output}" >&2
fi

## Self-test the FAIL gate: a forced failure must make the script exit non-zero.
if [ -n "${TEST_SELFCHECK_FAIL_GATE:-}" ]; then
   note_fail "self-test forced failure"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "dist-ai-style --detect: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "dist-ai-style --detect: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
