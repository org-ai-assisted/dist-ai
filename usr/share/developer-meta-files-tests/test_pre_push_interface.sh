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
DET="${tool_test_dir}/../../bin/pre-push-detect"
[ -x "${DET}" ] || DET='/usr/bin/pre-push-detect'
FIX="${tool_test_dir}/../../bin/pre-push-fix"
[ -x "${FIX}" ] || FIX='/usr/bin/pre-push-fix'
GATE="${tool_test_dir}/../../bin/pre-push-static"
[ -x "${GATE}" ] || GATE='/usr/bin/pre-push-static'
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
out="$("${DET}" "${test_dir}/tree" 2>/dev/null || true)"
if grep --quiet --fixed-strings 'R-120' <<< "${out}"; then
   note_pass "detector recurses a directory and flags a nested file"
else
   note_fail "detector did not recurse the directory"
fi

## --- detector: a missing path is a loud error, not a silent pass ------------
rc=0; "${DET}" "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "detector errors (exit 2) on a missing path"
else
   note_fail "detector did not error on a missing path (rc=${rc})"
fi

## --- fixer: directory recurses ('--check' non-zero on a fixable nested file)-
printf '%s\n' '#!/bin/bash' 'grep -q x /dev/null || true' \
   > "${test_dir}/tree/sub/fixable.sh"
rc=0; "${FIX}" --check "${test_dir}/tree" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 1 ]; then
   note_pass "fixer recurses a directory (--check finds a nested fixable file)"
else
   note_fail "fixer did not recurse the directory (rc=${rc})"
fi
rc=0; "${FIX}" --check "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "fixer errors (exit 2) on a missing path"
else
   note_fail "fixer did not error on a missing path (rc=${rc})"
fi

## --- gate --files: full-rule-set lint of a path on disk, no git -------------
gate_out="$("${GATE}" --files -- "${test_dir}/tree/sub/bad.sh" 2>&1 || true)"
if grep --quiet --fixed-strings 'R-120' <<< "${gate_out}"; then
   note_pass "gate --files runs the full rule set on a given file"
else
   note_fail "gate --files did not flag the violation"
fi
## A missing --files path must NOT read as 'all passed' (subshell-exit trap).
rc=0; "${GATE}" --files -- "${test_dir}/no-such" >/dev/null 2>&1 || rc=$?
if [ "${rc}" -eq 2 ]; then
   note_pass "gate --files errors on a missing path (no false green)"
else
   note_fail "gate --files silently passed a missing path (rc=${rc})"
fi

## --- silent-green guard: a crashing detector fails the gate -----------------
## A stub detector that exits 3 (a crash) beside a copy of the gate. The gate
## must FAIL, not read the empty output as 'no findings'.
mkdir --parents -- "${test_dir}/crash"
cp -- "${GATE}" "${test_dir}/crash/pre-push-static"
printf '%s\n' '#!/bin/bash' 'printf "boom\n" >&2' 'exit 3' \
   > "${test_dir}/crash/pre-push-detect"
chmod +x -- "${test_dir}/crash/pre-push-detect"
printf '%s\n' '#!/bin/bash' 'set -o errexit' 'true' \
   > "${test_dir}/crash/subject.sh"
crash_out="$("${test_dir}/crash/pre-push-static" --files -- \
   "${test_dir}/crash/subject.sh" 2>&1 || true)"
if grep --quiet --fixed-strings 'crashed' <<< "${crash_out}"; then
   note_pass "a detector crash is a hard gate FAILURE, not a silent green"
else
   note_fail "a detector crash was not caught (silent green risk)"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "pre-push-interface: ${passc} pass, ${fail} fail, 0 skip -- FAILURES above." >&2
   exit 1
fi
printf '%s\n' "pre-push-interface: ${passc} pass, 0 fail, 0 skip -- all assertions passed."
exit 0
