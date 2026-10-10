#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-varname-snapshot takes one optional output-dir. An option-looking word
## ('--help', a typo'd '--contarct') must never be taken AS that directory: the
## tool would create it and fill it with ~60 snapshot files in the caller's cwd.
## Asserts: --help prints usage and exits 0; an unknown option and a second
## positional exit 2; all three decide BEFORE resolving the derivative-maker
## checkout (the step that precedes creating the output dir), so no checkout is
## needed and none is mentioned in the output.
## Canary: fails on the parser that appended every non-'--contract' word to the
## positionals (--help became the output dir).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

tool="${test_dir}/../../bin/dm-varname-snapshot"
if [ ! -x "${tool}" ]; then
   tool="$(type -P dm-varname-snapshot || true)"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "FATAL: dm-varname-snapshot not found." >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

## run_case <expected-rc> <label> <args...>: run in an empty cwd, with a
## nonexistent checkout so a parser that falls through fails rather than
## snapshotting the real tree; assert rc and that checkout resolution was never
## reached (a fall-through prints a checkout FATAL/INFO line).
run_case() {
   local expected_rc="$1" label="$2"
   shift 2
   local case_dir rc=0
   case_dir="$(mktemp --directory --tmpdir="${work_dir}")"
   ( cd -- "${case_dir}" \
      && DERIVATIVE_MAKER_DIR="${work_dir}/no-such-checkout" "${tool}" "$@" ) \
      > "${case_dir}.out" 2>&1 || rc="$?"
   if [ "${rc}" -eq "${expected_rc}" ] \
      && ! grep --quiet --ignore-case -- 'checkout' "${case_dir}.out"; then
      pass "${label}: exit ${rc}, decided before touching the checkout"
   else
      fail "${label}: exit ${rc} (want ${expected_rc}), output: $(cat -- "${case_dir}.out")"
   fi
}

run_case 0 "--help" --help
run_case 2 "unknown option" --contarct
run_case 2 "two output dirs" out-a out-b

if grep --quiet --fixed-strings -- 'Usage: dm-varname-snapshot' <<< "$("${tool}" --help 2>&1)"; then
   pass "--help prints usage"
else
   fail "--help did not print usage"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: dm-varname-snapshot never takes an option as its output dir."
