#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## exit_with_error() takes an exit code as its FIRST arg (every call site is `exit_with_error 1 "..."`) and the
## rest as the message. Without shifting that arg off, it leaked into make_output_error's
## message as a spurious leading token ("ERROR: 1 <msg>") -- garbling every error the tool
## emits and breaking anything matching on the exact text -- while the code was ignored and
## the exit was hardcoded 1. This asserts the message is clean AND the code is honoured.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}
trap error_handler ERR

## Shared genmkfile library discovery + checkout capability gate (sibling suites
## source the same helper, so they cannot drift to different subjects/skips).
_common_dir="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common"
[ -r "${_common_dir}/genmkfile-locate.bash" ] || _common_dir="/usr/share/dist-ai-tests-common"
# shellcheck source=../dist-ai-tests-common/genmkfile-locate.bash
source "${_common_dir}/genmkfile-locate.bash"
genmkfile_require_helper
# shellcheck disable=SC2154  ## set by genmkfile_require_helper in the sourced helper
helper_file="${genmkfile_helper_file}"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

## Source the REAL helper WHOLE, then stub only what must be neutral. The helper is a
## sourced-only library (its CLI body is was_executed-gated), so sourcing defines
## exit_with_error, make_output_error AND every sibling they reach without running the CLI.
## A single-function sed cut silently drifts the moment a subject gains an intra-file
## dependency -- exactly the extract-a-function anti-pattern dist-ai's CLAUDE.md forbids.
## make_output_error sources trace.bsh (|| true when absent) and paints with $red/$bold/etc.
## Neutralise the environment so the subjects run in isolation; the function_trace stub is
## defined AFTER the source so it overrides the helper's own.
export HELPER_SCRIPTS_PATH="${test_root}/absent"
red='' bold='' cyan='' reset='' make_source_package_name='testpkg'
export red bold cyan reset make_source_package_name
# shellcheck disable=SC1090
source "${helper_file}"
if ! declare -F exit_with_error >/dev/null || ! declare -F make_output_error >/dev/null; then
   printf '%s\n' "ERROR: exit_with_error/make_output_error not defined after sourcing the helper." >&2
   exit 1
fi
# shellcheck disable=SC2317
function_trace() { printf '%s' ''; }

tests_total=0
tests_failed=0

## exit_with_error runs 'exit', so invoke it in a subshell and capture message + code together.
run_die() {
   local out rc
   out="$( ( exit_with_error "$@" ) 2>&1 )" && rc=0 || rc=$?
   printf '%s\n' "${out}"
   return "${rc}"
}

## want_rc defaults to code; pass it explicitly for the guarded cases where the code is
## clamped (a fatal error must never exit 0 / a wrapped-to-0 / a non-numeric).
check() {
   local desc="$1" code="$2" msg="$3" want_rc="${4:-$2}"
   local out rc
   out="$(run_die "${code}" "${msg}")" && rc=0 || rc=$?
   tests_total=$(( tests_total + 1 ))
   ## message carries "ERROR: <msg>" and NOT a spurious leading code token; exit == want_rc.
   if [[ "${out}" == *"ERROR: ${msg}"* ]] \
      && [[ "${out}" != *"ERROR: ${code} ${msg}"* ]] \
      && [ "${rc}" -eq "${want_rc}" ]; then
      printf '%s\n' "PASS  exit_with_error ${code} '${msg}' -> clean message, exit ${rc} (${desc})"
   else
      tests_failed=$(( tests_failed + 1 ))
      printf '%s\n' "FAIL  exit_with_error ${code} '${msg}' (${desc})" >&2
      printf '%s\n' "        want exit=${want_rc} got exit=${rc} out=[${out}]" >&2
   fi
}

check 'clean message, exit honoured' 1 'DEBEMAIL is empty'
check 'non-1 code honoured' 3 'some failure'
## A fatal error must never report success or an out-of-range code -> clamp to 1.
check 'code 0 clamped to 1' 0 'must not succeed' 1
check 'out-of-range code clamped to 1' 300 'out of range' 1
check 'non-numeric code clamped to 1' abc 'not a number' 1

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "exit_with_error_exit_code_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "exit_with_error_exit_code_test: ${tests_total} pass, 0 fail, 0 skip"
