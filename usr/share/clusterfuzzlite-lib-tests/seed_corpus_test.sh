#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Exercises cflite_explode_hex_corpus in the shared clusterfuzzlite-lib against
## the three reintroducible seed-loop traps it guards: a final line with no
## trailing newline must still be decoded (not silently dropped), a NAME
## carrying `/` or `..` must FATAL rather than escape the output dir, and a
## corpus that yields zero seeds must FATAL with a clear message rather than
## crash the later zip step. `cat` stands in for the hex decoder: the loop, not
## the decoding, is the subject here, so the output files' contents do not
## matter -- only which files are created, the count, and the exit status.

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

lib="${test_dir}/../clusterfuzzlite-lib/seed-corpus.bash"
if [ ! -f "${lib}" ]; then
   lib='/usr/share/clusterfuzzlite-lib/seed-corpus.bash'
fi
if [ ! -f "${lib}" ]; then
   printf '%s\n' 'SKIP: seed_corpus_test: clusterfuzzlite-lib not found' >&2
   exit 77  ## style-ok: allow-skip: shared library not present to test
fi
# shellcheck disable=SC1090
source "${lib}"

work_dir="$(mktemp --directory -- "${TMP}/seed-corpus-test.XXXXXX")"

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

## Case 1: a final line with no trailing newline must still be decoded.
seeds1="${work_dir}/seeds1.txt"
out1="${work_dir}/out1"
mkdir -- "${out1}"
printf 'first 6869\n## a comment\nlastseed 7a7a' > "${seeds1}"
count1="$(cflite_explode_hex_corpus "${seeds1}" cat "${out1}")"
assert 'counts both real seeds' test "${count1}" = '2'
assert 'first seed written' test -f "${out1}/first"
assert 'final no-newline seed written (not dropped)' test -f "${out1}/lastseed"

## Case 2a: a NAME containing `/` must FATAL and write nothing outside out_dir.
seeds2="${work_dir}/seeds2.txt"
out2="${work_dir}/out2"
mkdir -- "${out2}"
err2="${work_dir}/err2"
printf 'ok 6161\nevil/escape 6262\n' > "${seeds2}"
rc2=0
cflite_explode_hex_corpus "${seeds2}" cat "${out2}" >/dev/null 2>"${err2}" || rc2=$?
assert 'slash name returns non-zero' test "${rc2}" -ne 0
assert 'slash name prints a clear FATAL' grep -q 'unsafe seed name' "${err2}"
assert 'slash name creates no escaping subdir' test '!' -e "${out2}/evil"

## Case 2b: a NAME containing `..` must FATAL too (the non-slash arm).
seeds2b="${work_dir}/seeds2b.txt"
out2b="${work_dir}/out2b"
mkdir -- "${out2b}"
err2b="${work_dir}/err2b"
printf 'ok 6161\nfoo..bar 6262\n' > "${seeds2b}"
rc2b=0
cflite_explode_hex_corpus "${seeds2b}" cat "${out2b}" >/dev/null 2>"${err2b}" || rc2b=$?
assert 'dotdot name returns non-zero' test "${rc2b}" -ne 0
assert 'dotdot name prints a clear FATAL' grep -q 'unsafe seed name' "${err2b}"

## Case 3: a corpus that yields zero seeds must FATAL with a clear message.
seeds3="${work_dir}/seeds3.txt"
out3="${work_dir}/out3"
mkdir -- "${out3}"
err3="${work_dir}/err3"
printf '## only a comment\n\n' > "${seeds3}"
rc3=0
cflite_explode_hex_corpus "${seeds3}" cat "${out3}" >/dev/null 2>"${err3}" || rc3=$?
assert 'empty corpus returns non-zero' test "${rc3}" -ne 0
assert 'empty corpus prints a clear no-seeds FATAL' \
   grep -q 'no seeds decoded' "${err3}"

## Case 4: a line with a name but no hex is skipped, not counted or fatal.
seeds4="${work_dir}/seeds4.txt"
out4="${work_dir}/out4"
mkdir -- "${out4}"
printf 'nohex\nwith 6161\n' > "${seeds4}"
count4="$(cflite_explode_hex_corpus "${seeds4}" cat "${out4}")"
assert 'name-without-hex line skipped, only the valid seed counted' \
   test "${count4}" = '1'

## Case 5: a NAME of exactly '.' must FATAL (it would otherwise redirect into the
## output directory itself and crash with a confusing "Is a directory" error).
seeds5="${work_dir}/seeds5.txt"
out5="${work_dir}/out5"
mkdir -- "${out5}"
err5="${work_dir}/err5"
printf 'ok 6161\n. 6262\n' > "${seeds5}"
rc5=0
cflite_explode_hex_corpus "${seeds5}" cat "${out5}" >/dev/null 2>"${err5}" || rc5=$?
assert 'dot name returns non-zero' test "${rc5}" -ne 0
assert 'dot name prints a clear FATAL' grep -q 'unsafe seed name' "${err5}"

## Case 6: a decoder (or write) failure must FATAL, never be silently counted --
## even when the caller invokes the function in an || list (errexit disabled).
seeds6="${work_dir}/seeds6.txt"
out6="${work_dir}/out6"
mkdir -- "${out6}"
err6="${work_dir}/err6"
printf 'bad deadbeef\n' > "${seeds6}"
rc6=0
cflite_explode_hex_corpus "${seeds6}" false "${out6}" >/dev/null 2>"${err6}" || rc6=$?
assert 'decoder failure returns non-zero' test "${rc6}" -ne 0
assert 'decoder failure prints a clear FATAL' grep -q 'decode failed' "${err6}"

## Case 7: parsing is independent of the caller's IFS (a narrowed IFS must not
## fold "NAME HEX" into a single field).
seeds7="${work_dir}/seeds7.txt"
out7="${work_dir}/out7"
mkdir -- "${out7}"
printf 'one 61\ntwo 62\n' > "${seeds7}"
count7="$(IFS=$'\n'; cflite_explode_hex_corpus "${seeds7}" cat "${out7}")"
assert 'narrowed caller IFS still parses NAME<space>HEX' test "${count7}" = '2'
assert 'narrowed IFS: a seed file is written' test -f "${out7}/one"

if [ "${failures}" -eq 0 ]; then
   printf '%s\n' 'seed_corpus_test: all checks passed'
   exit 0
fi
printf 'seed_corpus_test: %s check(s) failed\n' "${failures}" >&2
exit 1
