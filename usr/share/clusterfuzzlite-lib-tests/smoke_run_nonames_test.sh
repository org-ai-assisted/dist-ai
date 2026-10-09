#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards the no-names branch of cflite_smoke_run_fuzzers in the shared
## clusterfuzzlite-lib: calling it with zero fuzzer names is itself the
## silent-skip class the guard exists to catch (nothing gets smoke-run), so it
## must FATAL rather than pass vacuously. The full smoke-run of a compiled fuzzer
## needs the OSS-Fuzz container and is out of scope for a unit test; this branch
## is the one reachable without one.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

test_script="$(readlink --canonicalize -- "${BASH_SOURCE[0]}")"
test_dir="${test_script%/*}"

lib="${test_dir}/../clusterfuzzlite-lib/smoke-run.bash"
if [ ! -f "${lib}" ]; then
   lib='/usr/share/clusterfuzzlite-lib/smoke-run.bash'
fi
if [ ! -f "${lib}" ]; then
   printf '%s\n' 'SKIP: smoke_run_nonames_test: clusterfuzzlite-lib not found' >&2
   exit 77  ## style-ok: allow-skip: shared library not present to test
fi
# shellcheck disable=SC1090
source "${lib}"

work_dir="$(mktemp --directory -- "${TMP}/smoke-run-nonames-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   ## Our own mktemp directory; an absent safe-rm is tolerated, not a fallback.
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}
trap cleanup_work_dir EXIT

failures=0

assert() {
   local desc="$1"
   shift
   if "$@"; then
      printf '%s\n' "PASS: ${desc}"
   else
      printf '%s\n' "FAIL: ${desc}" >&2
      failures=$(( failures + 1 ))
   fi
}

err="${work_dir}/err"
rc=0
cflite_smoke_run_fuzzers 2>"${err}" || rc=$?
assert 'no-names returns non-zero' test "${rc}" -ne 0
assert 'no-names prints a clear FATAL' \
   grep -q 'called with no fuzzer names' "${err}"

if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'smoke_run_nonames_test: all checks passed'
   exit 0
fi
printf '%s\n' "smoke_run_nonames_test: ${failures} check(s) failed" >&2
exit 1
