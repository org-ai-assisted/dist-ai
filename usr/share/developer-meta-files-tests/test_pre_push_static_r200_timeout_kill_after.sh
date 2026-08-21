#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for R-200 (timeout must carry a kill-after option), both
## sides:
##  (1) pre-push-static FLAGS a 'timeout' in COMMAND position with no kill-after
##      option -- at line start, after a separator, in an 'if', behind a leading
##      assignment, inside '$( ... )', or with a non-kill-after option
##      ('--signal=TERM') -- while SPARING one that carries '--kill-after='/'-k',
##      a 'timeout' inside a string ('x="timeout 5"'), a 'timeout' used as
##      another command's argument, and any file bearing the
##      '## style-ok: allow-bare-timeout' waiver.
##  (2) pre-push-fix INSERTS '--kill-after=<N>' into a bare literal-duration
##      'timeout <N> cmd', LEAVES untouched an option-carrying / expression-
##      duration / string-embedded timeout, a timeout whose wrapped command
##      carries a literal 'timeout <N>' argument, a keyword-as-argument line, and
##      any HEREDOC body or multi-line-quote body (shell DATA), and is idempotent.
##
## Fixture bodies are ASSEMBLED from fragments so no command-position
## 'timeout <N>' appears literally on a source line of THIS tracked file -- the
## gate scans it too, and a waiver would then hide a real hit. The assertions
## match the gate's FAIL line ('FAIL R-200') rather than a bare 'R-200', so the
## rule's own waiver-SKIP note (which also contains 'R-200') is not mistaken for
## a violation. The greps use 'grep --fixed-strings ... >/dev/null' (no quiet
## flag), itself R-161/R-200-compliant.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
if ! has git ; then
   printf '%s\n' "FATAL: git not on PATH" >&2
   exit 1
fi

## Resolve the tools RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/)
## so a developer editing the in-tree copies tests those, not the packaged ones.
tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${tool_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi
FIX="${tool_dir}/../../bin/pre-push-fix"
if [ ! -x "${FIX}" ]; then
   FIX='/usr/bin/pre-push-fix'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## Fragments, assembled so a command-position 'timeout <N>' never appears
## literally on a source line of this file.
tmo='timeout'
ka='--kill-after'
ks='-k'
sig='--signal=TERM'
sc=';'
hash='#'
dq='"'
bs=$'\\'

fixture_prologue=(
   '#!/bin/bash'
   ''
   'set -o errexit'
   'set -o nounset'
   'set -o pipefail'
   'set -o errtrace'
   'shopt -s inherit_errexit'
   'shopt -s shift_verbose'
   ''
)

body_of() {
   printf '%s\n' "${fixture_prologue[@]}" "$@"
}

## Builds a one-file repo around a script body; sets gate_output and gate_rc.
run_gate_on_body() {
   local name body repo base_sha
   name="$1"
   body="$2"
   repo="${test_dir}/gate-${name}"
   mkdir --parents -- "${repo}/usr/bin"
   printf '%s\n' "${body}" >"${repo}/usr/bin/subject"
   chmod 0755 -- "${repo}/usr/bin/subject"
   git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --allow-empty --message "base"
   base_sha="$(git -C "${repo}" rev-parse HEAD)"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --message "fixture"
   gate_rc=0
   gate_output="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || gate_rc=$?
}

## assert_flagged <name> <body> -- R-200 must appear.
assert_flagged() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "FAIL R-200" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "PASS: R-200 flagged ${1}"
   else
      printf '%s\n' "FAIL: R-200 did NOT flag ${1}"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   fi
}

## assert_spared <name> <body> -- R-200 must NOT appear and the gate must be
## green (a spared construct is a valid one, so the whole fixture must pass).
assert_spared() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "FAIL R-200" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "FAIL: R-200 wrongly flagged ${1}"
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'FAIL R-200' | head -2
      fail=1
   elif [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: gate not green on spared fixture ${1} (rc=${gate_rc})"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   else
      printf '%s\n' "PASS: R-200 spared ${1}"
   fi
}

## --- (1) bare timeout in command position is FLAGGED ---
assert_flagged "bare"          "$(body_of "${tmo} 5 do_thing")"
assert_flagged "suffix"        "$(body_of "${tmo} 30s do_thing")"
assert_flagged "if"            "$(body_of "if ${tmo} 5 do_thing${sc} then" '   true' 'fi')"
assert_flagged "after-sep"     "$(body_of "seq 5${sc} ${tmo} 5 do_thing")"
assert_flagged "assign-prefix" "$(body_of "LC_ALL=C ${tmo} 5 do_thing")"
assert_flagged "signal-no-ka"  "$(body_of "${tmo} ${sig} 5 do_thing")"
assert_flagged "cmd-subst"     "$(body_of "printf '%s' \"\$(${tmo} 5 do_thing)\"")"

## --- (1) a kill-after option, a string, an argument, and the waiver SPARED ---
assert_spared "ka-long"        "$(body_of "${tmo} ${ka}=5 5 do_thing")"
assert_spared "ka-short"       "$(body_of "${tmo} ${ks} 5 10 do_thing")"
assert_spared "ka-after-signal" "$(body_of "${tmo} ${sig} ${ka}=5 5 do_thing")"
## Valid GNU syntax with SPACE-separated option values, long and short: a
## '--signal TERM'/'-s TERM' before the kill-after must not hide it (the value
## 'TERM' is not the kill-after, but the option run still carries one).
assert_spared "ka-space"       "$(body_of "${tmo} --signal TERM ${ka} 1 5 do_thing")"
assert_spared "ka-short-space" "$(body_of "${tmo} -s TERM ${ks} 1 5 do_thing")"
## The deferred 'x="timeout 5"' spelling -- timeout is string data, not a command.
assert_spared "in-string" \
   "$(body_of "deferred=${dq}${tmo} 5${dq}" "printf '%s' ${dq}\${deferred}${dq}")"
## timeout as another command's argument, not a command word.
assert_spared "as-argument"    "$(body_of "printf '%s' ${tmo} 5")"
## Per-script waiver exempts an otherwise-flagged bare timeout.
assert_spared "waiver" \
   "$(body_of "## style-ok: allow-bare-timeout" "${tmo} 5 do_thing")"
## An array ELEMENT: the '(' in 'cmd=(...)' is array syntax, not a command
## separator, so 'timeout' there is DATA, not a bare invocation.
assert_spared "array-element" \
   "$(body_of "cmd=(${tmo} 5 sleep 10)" "printf '%s' ${dq}\${cmd[@]}${dq}")"
## A timeout whose invocation is CONTINUED to the next line (the options, maybe
## '--kill-after', follow) must not be flagged on the 'timeout \\' line alone.
assert_spared "multiline" \
   "$(body_of "${tmo} ${bs}" "   ${ka}=5 5 do_thing")"
## Informational runs time no child and need no kill-after.
assert_spared "help"    "$(body_of "${tmo} --help")"
assert_spared "version" "$(body_of "${tmo} --version")"
## A function DEFINITION named timeout is not a timeout invocation.
assert_spared "funcdef" "$(body_of "${tmo} () {" '   true' '}')"
## A ZERO-duration timeout ('timeout 0') is a no-op -- it bounds nothing, so there
## is no SIGTERM to back with a kill-after; flagging it would demand a kill-after
## the fixer (rightly) will not add.
assert_spared "zero-duration" "$(body_of "${tmo} 0 do_thing")"
## The no-op exemption covers EVERY all-zero GNU duration spelling, not only a
## bare '0': a leading-dot '.0' and a trailing-dot '0.' are zero too. Flagging
## them would demand a kill-after the fixer (rightly) refuses to add.
assert_spared "zero-leading-dot"  "$(body_of "${tmo} .0 do_thing")"
assert_spared "zero-trailing-dot" "$(body_of "${tmo} 0. do_thing")"
## A file defining its OWN timeout() function: every call targets that function,
## not coreutils, so R-200 skips the whole file.
assert_spared "local-timeout-def" \
   "$(body_of "${tmo} () { command ${tmo} ${dq}\${@}${dq}${sc} }" "${tmo} 5 do_thing")"

## --- (2) pre-push-fix behaviour ---
run_fix() {
   local name body file
   name="$1"
   body="$2"
   file="${test_dir}/fix-${name}.sh"
   printf '%s\n' '#!/bin/bash' "${body}" >"${file}"
   "${FIX}" "${file}" >/dev/null 2>&1 || true
   fix_result="$(cat -- "${file}")"
}

## A bare literal-duration timeout is expanded with a matching kill-after.
run_fix "expand" "${tmo} 5 do_thing"
if grep --fixed-strings -- "${tmo} ${ka}=5 5 do_thing" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix inserted --kill-after into a bare timeout"
else
   printf '%s\n' "FAIL: pre-push-fix did not insert --kill-after"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## A suffixed duration is copied verbatim into the kill-after option.
run_fix "expand-suffix" "${tmo} 30s do_thing"
if grep --fixed-strings -- "${tmo} ${ka}=30s 30s do_thing" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded a suffixed duration"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand a suffixed duration"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## A leading assignment does not stop the expansion (timeout IS the command).
run_fix "assign-expand" "LC_ALL=C ${tmo} 5 do_thing"
if grep --fixed-strings -- "LC_ALL=C ${tmo} ${ka}=5 5 do_thing" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded behind an assignment"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand behind an assignment"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## Idempotent: a second pass over the fixer's own output changes nothing.
run_fix "idempotent" "${tmo} 5 do_thing"
first="${fix_result}"
"${FIX}" "${test_dir}/fix-idempotent.sh" >/dev/null 2>&1 || true
if [ "${first}" = "$(cat -- "${test_dir}/fix-idempotent.sh")" ]; then
   printf '%s\n' "PASS: pre-push-fix is idempotent"
else
   printf '%s\n' "FAIL: pre-push-fix is not idempotent"
   printf '%s\n' "$(cat -- "${test_dir}/fix-idempotent.sh")"
   fail=1
fi

## A POSITIVE duration in an unusual-but-valid GNU spelling is still expanded: a
## leading zero ('05') and a trailing dot ('5.') are positive, so the fixer must
## add a kill-after -- otherwise the gate flags a line the fixer cannot fix (an
## unresolvable lint loop). Every format the gate flags, the fixer must handle.
run_fix "leading-zero-dur" "${tmo} 05 do_thing"
if grep --fixed-strings -- "${tmo} ${ka}=05 05 do_thing" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded a leading-zero duration"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand a leading-zero duration"
   printf '%s\n' "${fix_result}"
   fail=1
fi

run_fix "trailing-dot-dur" "${tmo} 5. do_thing"
if grep --fixed-strings -- "${tmo} ${ka}=5. 5. do_thing" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded a trailing-dot duration"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand a trailing-dot duration"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## SAFETY: the fixer must never rewrite an option-carrying, expression-duration,
## string-embedded, comment, or argument timeout -- each comes back byte-for-byte.
assert_fix_unchanged() {
   local name body
   name="$1"
   body="$2"
   run_fix "${name}" "${body}"
   if [ "${fix_result}" = "$(printf '%s\n' '#!/bin/bash' "${body}")" ]; then
      printf '%s\n' "PASS: pre-push-fix left ${name} unchanged"
   else
      printf '%s\n' "FAIL: pre-push-fix modified ${name}"
      printf '%s\n' "${fix_result}"
      fail=1
   fi
}
## An option before the duration: the fixer cannot skip a space-separated option
## value safely, so it bails and the gate reports it.
assert_fix_unchanged "opt-signal" "${tmo} ${sig} 5 do_thing"
## An expression duration cannot be copied into a kill-after literal.
assert_fix_unchanged "expr-duration" "${tmo} ${dq}\${T}${dq} do_thing"
## timeout inside a string is data, not a command.
assert_fix_unchanged "instring" "deferred=${dq}${tmo} 5${dq}"
## timeout after a comment is comment text.
assert_fix_unchanged "in-comment" "true ${hash} note${sc} ${tmo} 5 do_thing"
## timeout as an argument to another command.
assert_fix_unchanged "argument" "printf '%s' ${tmo} 5"
## An ARRAY element -- 'cmd=(timeout 5 x)' is DATA, not a command: the '(' is
## array syntax. The fixer must not rewrite it.
assert_fix_unchanged "array-element" "cmd=(${tmo} 5 sleep 10)"
## A multi-line string that CLOSES one quote and OPENS another on the same line:
## the 'timeout' on the next line is inside the reopened string (DATA). A scanner
## that stopped at the first closing quote would lose the reopened-quote state
## and rewrite the string.
mlquote_reopen="$(printf '%s\n' \
   "a=${dq}one" "two${dq} ${sc} b=${dq}three" "${tmo} 5 inside-b${dq}")"
assert_fix_unchanged "mlquote-reopen" "${mlquote_reopen}"
## A file that WAIVES R-200 keeps its deliberately-bare timeout: the fixer must
## honor '## style-ok: allow-bare-timeout' just as the gate does.
assert_fix_unchanged "waived" \
   "$(printf '%s\n' '## style-ok: allow-bare-timeout' "${tmo} 5 do_thing")"
## A leading-option timeout whose WRAPPED command carries a literal 'timeout <N>'
## argument: the anchored duration regex must not wander onto that argument.
assert_fix_unchanged "opt-then-arg" "${tmo} ${sig} 5 echo ${tmo} 5"
## A control keyword passed as a literal ARGUMENT is not command position.
assert_fix_unchanged "keyword-arg" "echo then ${tmo} 5 x"
## A ZERO-duration timeout is a no-op; the fixer must NOT emit '--kill-after=0'.
assert_fix_unchanged "zero-duration" "${tmo} 0 do_thing"
## ... in EVERY all-zero spelling, so a loosened duration regex can never start
## emitting a disabled '--kill-after=0'.
assert_fix_unchanged "zero-leading-dot"  "${tmo} .0 do_thing"
assert_fix_unchanged "zero-trailing-dot" "${tmo} 0. do_thing"
## A file defining its own timeout(): the fixer DECLINES it -- a call targets the
## function, and rewriting it to '--kill-after=5 5 ...' would corrupt its args.
assert_fix_unchanged "local-timeout-def" \
   "$(printf '%s\n%s' "${tmo} () { command ${tmo} ${dq}\${@}${dq}${sc} }" "${tmo} 5 do_thing")"

## --- (2b) heredoc / multi-line-quote bodies are shell DATA, never rewritten ---
heredoc_body="$(printf '%s\n' "cat <<EOF" "${tmo} 5 body" "EOF")"
assert_fix_unchanged "heredoc-body" "${heredoc_body}"
## A quoted-delimiter heredoc body is data too.
heredoc_quoted="$(printf '%s\n' "cat <<'EOF'" "${tmo} 5 body" "EOF")"
assert_fix_unchanged "heredoc-quoted" "${heredoc_quoted}"
## A line inside an unterminated multi-line double-quote is data.
mlquote_body="$(printf '%s\n' "msg=${dq}line one" "${tmo} 5 still-in-string${dq}")"
assert_fix_unchanged "mlquote-body" "${mlquote_body}"
## A line CONTINUED from the previous command ('echo \') is that command's
## arguments, not a fresh command word.
continuation="$(printf '%s\n' "echo ${bs}" "${tmo} 5 cmd")"
assert_fix_unchanged "line-continuation" "${continuation}"
## A '<<' bit-shift reads as a heredoc marker too, so the WHOLE file is declined
## (over-conservative but safe -- the gate still reports the timeout after it).
arith_declined="$(printf '%s\n' "y=\$((x << n))" "${tmo} 5 real")"
assert_fix_unchanged "arith-declined" "${arith_declined}"
## A heredoc file is declined WHOLESALE: the body AND a real command after the
## terminator are BOTH left untouched (the gate reports them). No shell parser,
## no per-line rescue -- the hard rule keeps the fixer off multi-line data.
heredoc_then_cmd="$(printf '%s\n' "cat <<EOF" "${tmo} 5 body" "EOF" "${tmo} 5 real")"
assert_fix_unchanged "heredoc-declined-with-cmd" "${heredoc_then_cmd}"
## A backslash in a '#' comment tail is comment TEXT, not a continuation, so the
## file stays SIMPLE and the command on the next line IS fixed.
run_fix "comment-backslash" "$(printf '%s\n' "true ${hash} note ${bs}" "${tmo} 5 cmd")"
if grep --fixed-strings -- "${tmo} ${ka}=5 5 cmd" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: a comment-tail backslash keeps the file simple (fixed)"
else
   printf '%s\n' "FAIL: a comment-tail backslash wrongly declined the file"
   printf '%s\n' "${fix_result}"
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
