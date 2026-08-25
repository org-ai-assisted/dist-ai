#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Interface tests for the parser-backed tooling: file/folder arguments and the
## non-git --files lint mode. Pins two silent-green guards:
##   * a DIRECTORY argument recurses (it used to be skipped -> exit 0, checking
##     nothing while reading as a pass);
##   * a MISSING path is a loud non-zero error, never a silent success;
##   * a DETECTOR CRASH (any exit other than 0/1-with-findings/2) is a hard gate
##     FAILURE, not "no findings".

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

tool_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
STYLE="${tool_test_dir}/../../bin/dist-ai-style"
[ -x "${STYLE}" ] || STYLE='/usr/bin/dist-ai-style'
## The detector and fixer are modes of the one tool.
run_det() { "${STYLE}" --detect "$@"; }
run_fix() { "${STYLE}" --fix "$@"; }
GATE="${tool_test_dir}/../../bin/dist-ai-style"
[ -x "${GATE}" ] || GATE='/usr/bin/dist-ai-style'
for prereq in shfmt python3 safe-rm shellcheck ; do
   type -P "${prereq}" >/dev/null 2>&1 || {
      printf '%s\n' "FATAL: '${prereq}' not on PATH; this test cannot run." >&2
      exit 1
   }
done

test_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${test_dir}"; }
trap cleanup EXIT

passc=0
fail=0
note_pass() { printf '%s\n' "PASS: ${1}" ; passc=$(( passc + 1 )) ; }
note_fail() { printf '%s\n' "FAIL: ${1}" >&2 ; fail=$(( fail + 1 )) ; }

## A tree with one violating shell file, in a nested dir.
mkdir --parents -- "${test_dir}/tree/sub"
printf '%s\n' '#!/bin/bash' 'rm -rf /x' > "${test_dir}/tree/sub/bad.sh"
printf '%s\n' 'plain text, not shell' > "${test_dir}/tree/notes.txt"

## --- detector: directory recurses, finds the nested violation ---------------
out="$(run_det "${test_dir}/tree" 2>/dev/null || true)"
if grep --quiet --fixed-strings 'R-120' <<< "${out}"; then
   note_pass "detector recurses a directory and flags a nested file"
else
   note_fail "detector did not recurse the directory"
fi

## --- detector: a missing path is a loud error, not a silent pass ------------
rc=0; run_det "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "detector errors (exit 2) on a missing path"
else
   note_fail "detector did not error on a missing path (rc=${rc})"
fi

## --- fixer: directory recurses ('--check' non-zero on a fixable nested file)-
printf '%s\n' '#!/bin/bash' 'grep -q x /dev/null || true' \
   > "${test_dir}/tree/sub/fixable.sh"
rc=0; run_fix --check "${test_dir}/tree" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ]; then
   note_pass "fixer recurses a directory (--check finds a nested fixable file)"
else
   note_fail "fixer did not recurse the directory (rc=${rc})"
fi
rc=0; run_fix --check "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "fixer errors (exit 2) on a missing path"
else
   note_fail "fixer did not error on a missing path (rc=${rc})"
fi

## --- direct file lint: full per-file rule set on a path, no git --------------
gate_out="$("${GATE}" --check -- "${test_dir}/tree/sub/bad.sh" 2>&1 || true)"
if grep --quiet --fixed-strings 'R-120' <<< "${gate_out}"; then
   note_pass "direct --check runs the rule set on a given file"
else
   note_fail "direct --check did not flag the violation"
fi
## A missing path must NOT read as 'all passed' (subshell-exit trap).
rc=0; "${GATE}" --check -- "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "direct --check errors on a missing path (no false green)"
else
   note_fail "direct --check silently passed a missing path (rc=${rc})"
fi

## --- silent-green guard: a detect error is loud, never a silent 'no findings'
## An unreadable --message-file (a directory) cannot be checked, so detect exits
## non-zero (2), never 0 -- a caller must never read a failure to run as clean.
mkdir --parents -- "${test_dir}/crash/adir"
crash_rc=0
"${GATE}" --detect --message-file "${test_dir}/crash/adir" \
   "${test_dir}/tree/notes.txt" >/dev/null 2>&1 || crash_rc=$?
if [ "${crash_rc}" -ne 0 ]; then
   note_pass "a detect error is non-zero, not a silent green"
else
   note_fail "a detect error read as green (rc=${crash_rc})"
fi

## --- external checks run in the human front (dist-ai-style --check) ----------
## The check front is authoritative, so it runs bash -n + shellcheck (the AST
## '--detect' channel omits them -- multi-line tool output is not a machine
## record). A syntax error fails bash -n; an unparseable file the AST rules skip
## must still be caught here.
mkdir --parents -- "${test_dir}/ext"
printf '%s\n' '#!/bin/bash' 'if [ x ]' > "${test_dir}/ext/syntax.sh"
rc=0; out="$("${STYLE}" --check "${test_dir}/ext/syntax.sh" 2>&1)" || rc=$?
if [ "${rc}" -eq 1 ] && grep --quiet --fixed-strings 'bash -n' <<< "${out}"; then
   note_pass "check front runs bash -n (a syntax error fails)"
else
   note_fail "check front did not flag a bash -n syntax error (rc=${rc})"
fi
## shellcheck fires on a real finding (SC2086 unquoted expansion) when present;
## if shellcheck is absent it self-skips with a note (fail-open), so accept both.
printf '%s\n' '#!/bin/bash' 'set -o errexit' 'set -o nounset' 'set -o pipefail' \
   'set -o errtrace' 'shopt -s inherit_errexit' 'shopt -s shift_verbose' \
   'export LC_ALL=C' 'v="$1"' 'grep $v /dev/null || true' \
   > "${test_dir}/ext/sc.sh"
out="$("${STYLE}" --check "${test_dir}/ext/sc.sh" 2>&1 || true)"
if grep --quiet --extended-regexp 'shellcheck: |shellcheck not on PATH' <<< "${out}"; then
   note_pass "check front runs shellcheck (or self-skips when absent)"
else
   note_fail "check front neither ran nor skipped shellcheck"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-interface: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-interface: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
