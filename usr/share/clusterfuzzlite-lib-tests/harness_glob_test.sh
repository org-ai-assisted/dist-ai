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

## Case 4: a glob whose path contains a SPACE must not be word-split into a fake
## match -- an empty such directory still FATALs, a populated one returns intact.
space_dir="${work_dir}/a b"
mkdir -- "${space_dir}"
err4="${work_dir}/err4"
declare -a arr4=()
rc4=0
cflite_list_harnesses arr4 "${space_dir}/fuzz_*.py" 2>"${err4}" || rc4=$?
assert 'space-path zero-match returns non-zero' test "${rc4}" -ne 0
assert 'space-path zero-match leaves the array empty' test "${#arr4[@]}" -eq 0
touch -- "${space_dir}/fuzz_s.py"
declare -a arr4b=()
cflite_list_harnesses arr4b "${space_dir}/fuzz_*.py"
assert 'space-path match returns exactly the one harness' test "${#arr4b[@]}" -eq 1

## Case 5: a caller with noglob (set -f) must still get real expansion, so a
## zero match FATALs instead of returning the literal pattern -- and set -f must
## be restored afterward.
set -f
err5="${work_dir}/err5"
declare -a arr5=()
rc5=0
cflite_list_harnesses arr5 "${empty_dir}/fuzz_*.py" 2>"${err5}" || rc5=$?
noglob_after='off'
case "$-" in
   *f*)
      noglob_after='on'
      ;;
esac
set +f
assert 'set -f zero-match still returns non-zero' test "${rc5}" -ne 0
assert 'set -f zero-match leaves the array empty' test "${#arr5[@]}" -eq 0
assert 'set -f restored by the helper' test "${noglob_after}" = 'on'

## Case 6: a caller with failglob must still get the clean zero-match FATAL (the
## helper disables failglob for the expansion), with no spurious bash "no match"
## error, and failglob restored afterward.
shopt -s failglob
err6="${work_dir}/err6"
declare -a arr6=()
rc6=0
cflite_list_harnesses arr6 "${empty_dir}/fuzz_*.py" 2>"${err6}" || rc6=$?
failglob_after='off'
if shopt -q failglob; then
   failglob_after='on'
fi
shopt -u failglob
assert 'failglob zero-match returns non-zero' test "${rc6}" -ne 0
assert 'failglob zero-match leaves the array empty' test "${#arr6[@]}" -eq 0
assert 'failglob zero-match prints the clean FATAL' \
   grep --quiet 'no fuzz harnesses matched' "${err6}"
if grep --quiet 'no match' "${err6}"; then
   printf 'FAIL: %s\n' 'failglob leaked a bash "no match" error (not disabled)' >&2
   failures=$(( failures + 1 ))
else
   printf 'PASS: %s\n' 'failglob zero-match has no spurious bash "no match" error'
fi
assert 'failglob restored by the helper' test "${failglob_after}" = 'on'

if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'harness_glob_test: all checks passed'
   exit 0
fi
printf 'harness_glob_test: %s check(s) failed\n' "${failures}" >&2
exit 1
