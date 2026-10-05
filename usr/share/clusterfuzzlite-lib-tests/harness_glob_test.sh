#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Exercises cflite_list_harnesses in the shared clusterfuzzlite-lib. The guard's
## whole purpose is that a zero-match fails LOUD: nullglob alone would compile
## zero fuzzers and pass (silent green), and no nullglob would crash confusingly
## on the literal pattern. So the two assertions that matter most are that a
## zero-match returns non-zero with a clear message, and that a real match is
## returned intact without disturbing the caller's nullglob setting.

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

lib="${test_dir}/../clusterfuzzlite-lib/harness-glob.bash"
if [ ! -f "${lib}" ]; then
   lib='/usr/share/clusterfuzzlite-lib/harness-glob.bash'
fi
if [ ! -f "${lib}" ]; then
   printf '%s\n' 'SKIP: harness_glob_test: clusterfuzzlite-lib not found' >&2
   exit 77  ## style-ok: allow-skip: shared library not present to test
fi
# shellcheck disable=SC1090
source "${lib}"

work_dir="$(mktemp --directory -- "${TMP}/harness-glob-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   ## Our own mktemp directory; an absent safe-rm is tolerated, not a fallback.
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}
trap cleanup_work_dir EXIT

failures=0

## assert DESC CMD...  -- PASS when CMD succeeds, FAIL (and count) otherwise.
assert() {
   local desc="$1"
   shift
   if "$@"; then
      printf 'PASS: %s\n' "${desc}"
   else
      printf 'FAIL: %s\n' "${desc}" >&2
      failures=$(( failures + 1 ))
   fi
}

## Case 1: zero match MUST fail loud, never a silent empty success.
empty_dir="${work_dir}/empty"
mkdir -- "${empty_dir}"
err1="${work_dir}/err1"
declare -a arr1=()
rc1=0
cflite_list_harnesses arr1 "${empty_dir}/fuzz_*.py" 2>"${err1}" || rc1=$?
assert 'zero-match returns non-zero' test "${rc1}" -ne 0
assert 'zero-match leaves the array empty' test "${#arr1[@]}" -eq 0
assert 'zero-match prints a clear FATAL' \
   grep -q 'no fuzz harnesses matched' "${err1}"

## Case 2: a real match is returned intact, via the REAL bare-under-errexit
## calling convention a consumer build.sh uses. A non-zero return here -- e.g. a
## save/restore step that trips errexit on the normal match path -- ABORTS this
## script, which is the regression signal; reaching the assertions proves it
## returned 0. (A `|| rc=$?` call would disable errexit and MASK that class.)
full_dir="${work_dir}/full"
mkdir -- "${full_dir}"
touch -- "${full_dir}/fuzz_x.py"
touch -- "${full_dir}/fuzz_y.py"
touch -- "${full_dir}/notme.txt"
declare -a arr2=()
cflite_list_harnesses arr2 "${full_dir}/fuzz_*.py"
assert 'match populates exactly the two harnesses (bare call under errexit)' \
   test "${#arr2[@]}" -eq 2
found_x='no'
found_y='no'
for harness in "${arr2[@]}"; do
   case "${harness##*/}" in
      fuzz_x.py)
         found_x='yes'
         ;;
      fuzz_y.py)
         found_y='yes'
         ;;
   esac
done
assert 'fuzz_x.py matched' test "${found_x}" = 'yes'
assert 'fuzz_y.py matched' test "${found_y}" = 'yes'

## Case 3: the caller's nullglob setting is restored either way (arr2 reused as a
## throwaway sink; only the shopt state matters here).
shopt -u nullglob
cflite_list_harnesses arr2 "${full_dir}/fuzz_*.py" || true
nullglob_state='on'
if ! shopt -q nullglob; then
   nullglob_state='off'
fi
assert 'nullglob restored to off when caller had it off' \
   test "${nullglob_state}" = 'off'

shopt -s nullglob
cflite_list_harnesses arr2 "${full_dir}/fuzz_*.py" || true
nullglob_state='off'
if shopt -q nullglob; then
   nullglob_state='on'
fi
assert 'nullglob restored to on when caller had it on' \
   test "${nullglob_state}" = 'on'
shopt -u nullglob

if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'harness_glob_test: all checks passed'
   exit 0
fi
printf 'harness_glob_test: %s check(s) failed\n' "${failures}" >&2
exit 1
