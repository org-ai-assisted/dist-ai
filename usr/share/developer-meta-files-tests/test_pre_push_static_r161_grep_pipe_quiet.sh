#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for R-161 (grep quiet flag), both halves:
##  (1) pre-push-static FLAGS a quiet grep (-q/--quiet/--silent) that CONSUMES a
##      pipe -- it exits at the first match, SIGPIPEs the writer on the left, and
##      'set -o pipefail' fails the pipeline (141) -- while SPARING a here-string
##      and a plain file read (neither is a pipe).
##  (2) pre-push-static FLAGS a SHORT quiet cluster ('-q','-iq') in command
##      position, while SPARING the long form, a grep inside a string, and a
##      following '[ ... -eq N ]' test operator (which must not read as a short
##      quiet cluster).
##  (3) pre-push-fix EXPANDS a short quiet cluster to its long form, LEAVES an
##      arg-taking cluster and a string-embedded grep untouched, and does NOT
##      rewrite the pipe case (a redirect move is not a single-token edit).
##
## Fixture bodies are ASSEMBLED from fragments so no forbidden construct appears
## literally in THIS tracked file -- the gate scans it too, and a waiver would
## then hide a real hit. The assertion greps pipe into 'grep --fixed-strings ...
## >/dev/null' (no quiet flag), which is itself R-161-compliant.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
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
GATE="${tool_dir}/../../bin/dist-ai-style"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi
FIX="${tool_dir}/../../bin/dist-ai-style"
if [ ! -x "${FIX}" ]; then
   FIX='/usr/bin/dist-ai-style'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

fail=0

## Forbidden tokens, assembled so a flaggable construct never appears literally
## on a source line of this file.
pipe='|'
grp='grep'
ql='--quiet'
sil='--silent'
qs='-q'
iqs='-iq'
dd='--'
bs=$'\\'
sc=';'
hash='#'
dq='"'

fixture_prologue=(
   '#!/bin/bash'
   ''
   'set -o errexit'
   'set -o nounset'
   'set -o pipefail'
   'set -o errtrace'
   'shopt -s inherit_errexit'
   'shopt -s shift_verbose'
   'export LC_ALL=C'
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
   gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base_sha}" 2>&1 )" || gate_rc=$?
}

## assert_flagged <name> <body> -- R-161 must appear.
assert_flagged() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-161" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "PASS: R-161 flagged ${1}"
   else
      printf '%s\n' "FAIL: R-161 did NOT flag ${1}"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   fi
}

## assert_spared <name> <body> -- R-161 must NOT appear and the gate must be
## green (a spared construct is a valid one, so the whole fixture must pass).
assert_spared() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-161" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "FAIL: R-161 wrongly flagged ${1}"
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'R-161' | head -2
      fail=1
   elif [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: gate not green on spared fixture ${1} (rc=${gate_rc})"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   else
      printf '%s\n' "PASS: R-161 spared ${1}"
   fi
}

## --- (1) pipe + quiet is FLAGGED ---
assert_flagged "pipe-long"  "$(body_of "seq 5 ${pipe} ${grp} ${ql} 5")"
assert_flagged "pipe-short" "$(body_of "seq 5 ${pipe} ${grp} ${qs} bar")"
assert_flagged "pipe-silent" "$(body_of "seq 5 ${pipe} ${grp} ${sil} bar")"
## An UNAMBIGUOUS getopt_long abbreviation of '--quiet' is still a quiet flag, so
## a pipe-consuming '--qu' grep is FLAGGED. CANARY: the pre-abbrev exact-match
## code missed '--qu' (a false negative -- an unflagged pipefail/SIGPIPE bug).
assert_flagged "pipe-abbrev-quiet" "$(body_of "seq 5 ${pipe} ${grp} --qu bar")"
## A line-continued pipe whose quiet grep sits on a leading-'|' line.
assert_flagged "pipe-continued" \
   "$(body_of "seq 5 ${bs}" "   ${pipe} ${grp} ${ql} 5")"

## --- (1) here-string and file read are SPARED ---
assert_spared "herestring" \
   "$(body_of 'v="x"' "${grp} ${ql} ${dd} pat <<< \"\${v}\"")"
assert_spared "file-read"  "$(body_of "${grp} ${ql} ${dd} pat /etc/os-release")"
assert_spared "pipe-no-quiet" "$(body_of "seq 5 ${pipe} ${grp} 5")"

## --- (2) short quiet cluster is FLAGGED ---
assert_flagged "short-bare" "$(body_of "${grp} ${qs} x /etc/os-release")"
assert_flagged "short-if" \
   "$(body_of "if ${grp} ${iqs} kali /etc/os-release${sc} then" '   true' 'fi')"
assert_flagged "short-if-neg" \
   "$(body_of "if ! ${grp} ${qs} x /etc/os-release${sc} then" '   true' 'fi')"

## --- (2) long form, string-embedded grep, and '-eq' test are SPARED ---
assert_spared "long-file-read" "$(body_of "${grp} ${ql} x /etc/os-release")"
assert_spared "grep-in-string" \
   "$(body_of "printf '%s' \"run ${grp} ${qs} here\"")"
assert_spared "eq-test-operator" \
   "$(body_of "if [ \"\$(${grp} --count ${dd} x /etc/os-release)\" -eq 2 ]${sc} then" \
      '   true' 'fi')"

## --- (2b) reviewer-driven edge cases ---
## An OR-list '||' is not a pipe; grep reads the file, so a long quiet flag
## there is fine (was a false positive that read the second '|' as a pipe).
assert_spared "or-list" \
   "$(body_of "false ${pipe}${pipe} ${grp} ${ql} needle /etc/os-release")"
## '-eq' is '-e' with pattern 'q', not a quiet flag (arg-taker before 'q').
assert_spared "eq-bundled" "$(body_of "seq 5 ${pipe} ${grp} -eq foo")"
## 'in' heads a word list, not a command -- grep there is a literal word.
assert_spared "for-in-wordlist" \
   "$(body_of "for arg in ${grp} ${qs} foo${sc} do printf '%s' \"\${arg}\"${sc} done")"
## A leading 'VAR=value' assignment must not hide the violation (false negative).
assert_flagged "pipe-assign" \
   "$(body_of "seq 5 ${pipe} LC_ALL=C ${grp} ${ql} 5")"
assert_flagged "short-assign" \
   "$(body_of "LC_ALL=C ${grp} -Fq needle /etc/os-release")"
## A short quiet grep must still be caught when an UNRELATED piped grep shares
## the line (the old whole-line invert dropped it).
assert_flagged "short-with-unrelated-pipe" \
   "$(body_of "${grp} ${qs} x /etc/os-release ${pipe} ${grp} bar")"
assert_flagged "short-after-unrelated-pipe" \
   "$(body_of "seq 5 ${pipe} ${grp} x${sc} ${grp} ${qs} y /etc/os-release")"
## A command whose NAME merely starts with 'grep' (a wrapper) is not GNU grep.
assert_spared "grep-prefixed-command" \
   "$(body_of "${grp}wrap() { return 0${sc} }" "${grp}wrap ${qs} input")"
## 'grep -- <pattern>' where the pattern LOOKS like a flag is a search, not a
## quiet option (a quoted flag-pattern is spared; the unquoted form stays a
## documented residual).
assert_spared "dashdash-quiet-pattern" \
   "$(body_of "${grp} ${dd} '--quiet' /etc/os-release")"

## --- (3) pre-push-fix behaviour ---
run_fix() {
   local name body file
   name="$1"
   body="$2"
   file="${test_dir}/fix-${name}.sh"
   printf '%s\n' '#!/bin/bash' "${body}" >"${file}"
   "${FIX}" --fix "${file}" >/dev/null 2>&1 || true
   fix_result="$(cat -- "${file}")"
}

## A short cluster is expanded to the long form.
run_fix "expand" "if ${grp} ${iqs} kali /etc/os-release${sc} then true${sc} fi"
if grep --fixed-strings -- '--ignore-case --quiet' <<< "${fix_result}" >/dev/null \
   && ! grep --fixed-strings -- " ${iqs} " <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded a short quiet cluster"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand the short quiet cluster"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## An arg-taking cluster is left for the gate (a '-e' value could be misread).
run_fix "argtaker" "${grp} ${iqs} -e a /etc/os-release"
if grep --fixed-strings -- " ${iqs} " <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix left an arg-taking cluster untouched"
else
   printf '%s\n' "FAIL: pre-push-fix rewrote an arg-taking cluster"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## A grep inside a string is not command position, so it is not rewritten.
run_fix "instring" "printf '%s' \"run ${grp} ${qs} here\""
if grep --fixed-strings -- "run ${grp} ${qs} here" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix left a string-embedded grep untouched"
else
   printf '%s\n' "FAIL: pre-push-fix rewrote a grep inside a string"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## SAFETY: the fixer must never rewrite program DATA -- a grep inside a string
## (even one that opens with a separator, or with a control keyword) or after a
## comment stays byte-for-byte. Each fixture is fed verbatim and must come back
## unchanged.
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
## separator inside a double-quoted string.
assert_fix_unchanged "instring-sep" "printf '%s' \"run${sc} ${grp} ${qs} here\""
## CANARY: grep as an ARGUMENT after an inline-assignment + separator + command
## ('X=1;run grep -iq foo' -- grep is run's arg). A greedy assignment-value '\S*'
## swallowed the ';run' run and mis-read grep as command-position, mutating run's
## args. The value now stops at ';'/'&'/'|' (lockstep with the gate's _pkg_cmd_re).
assert_fix_unchanged "arg-after-inline-assign" "X=1${sc}run ${grp} ${iqs} foo"
## a control keyword inside a string.
assert_fix_unchanged "instring-keyword" "printf '%s' \"if ${grp} ${qs} x\""
## a trailing '#' comment.
assert_fix_unchanged "in-comment" "true ${hash} note${sc} ${grp} ${qs} file"
## 'in' word list -- grep is a literal iterated word.
assert_fix_unchanged "for-in" "for arg in ${grp} ${qs} foo${sc} do true${sc} done"
## An ESCAPED quote inside a double-quoted string must not fake a closed string.
assert_fix_unchanged "escaped-quote" \
   "printf ${dq}run ${bs}${dq}${sc} ${grp} ${qs} here${dq}"
## A comment that starts right after a metacharacter ('; #') is comment text.
assert_fix_unchanged "comment-after-semicolon" \
   "true${sc}${hash} note${sc} ${grp} ${qs} file"
## A backslash inside single quotes is LITERAL, so the '\' does not escape the
## following quote -- grep sits in the SECOND single-quoted string (data).
assert_fix_unchanged "single-quote-escape" \
   ": 'foo${bs}' 'run ${sc} ${grp} ${qs} here'"
## '\'-glued to a keyword is a different command name ('ifx'), not 'if grep'.
assert_fix_unchanged "backslash-keyword" "if${bs}x ${grp} ${qs} foo"

## A leading assignment does not stop the expansion (grep IS the command).
run_fix "assign-expand" "LC_ALL=C ${grp} ${qs} x /etc/os-release"
if grep --fixed-strings -- "LC_ALL=C ${grp} --quiet x" <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix expanded a short cluster behind an assignment"
else
   printf '%s\n' "FAIL: pre-push-fix did not expand behind an assignment"
   printf '%s\n' "${fix_result}"
   fail=1
fi

## The pipe case is NOT auto-fixed with a redirect (left for a human); the fixer
## only normalises the flag, so no '>/dev/null' is inserted.
run_fix "pipe-not-redirected" "seq 5 ${pipe} ${grp} ${ql} 5"
if ! grep --fixed-strings -- '/dev/null' <<< "${fix_result}" >/dev/null; then
   printf '%s\n' "PASS: pre-push-fix did not auto-insert a pipe redirect"
else
   printf '%s\n' "FAIL: pre-push-fix inserted a redirect for the pipe case"
   printf '%s\n' "${fix_result}"
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
