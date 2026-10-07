#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## image-test-result-emit ingests the account-owned step stderr tail and screenshot
## as root. It MUST open each no-follow and refuse a symlink, so an unprivileged
## producer cannot swap one in and make root read an off-limits target into the
## world-readable results plane (the TOCTOU the old `[ ! -L ]` pre-check could not
## close -- the emitter reopened the path later). Drives the REAL emitter; no root
## needed, the refusal is uid-independent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

emit="${IMAGE_TEST_RESULT_EMIT_BIN:-}"
if [ -z "${emit}" ]; then
   if [ -f "${test_dir}/../../bin/image-test-result-emit" ]; then
      emit="${test_dir}/../../bin/image-test-result-emit"
   else
      emit='/usr/bin/image-test-result-emit'
   fi
fi
[ -r "${emit}" ] || { printf 'FATAL: image-test-result-emit not found at %s\n' "${emit}" >&2; exit 1; }

workdir="$(mktemp --directory --tmpdir emit-nofollow-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## A neutral sentinel standing in for a symlink target the account must not be able
## to make root read (RFC-neutral, not an alarming path).
sentinel='SYMLINK-TARGET-SENTINEL-DO-NOT-LEAK'
printf '%s\n' "${sentinel}" > "${workdir}/target.txt"
printf '%s\n' 'genuine stderr tail' > "${workdir}/err.txt"
printf '%s' 'fake-png-bytes' > "${workdir}/shot.png"
ln --symbolic -- "${workdir}/target.txt" "${workdir}/err.symlink"
ln --symbolic -- "${workdir}/target.txt" "${workdir}/shot.symlink"

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s\n' "${label}"
      pass=$((pass + 1))
   else
      printf 'FAIL: %s (got %s, want %s)\n' "${label}" "${got}" "${want}"
      fail=$((fail + 1))
   fi
}

## Drive the emitter with a fixed run envelope; emit the exit code.
emit_rc() {
   local dest="$1"
   shift
   local rc=0
   "${emit}" \
      --run-id r-1 --lane testlane --builder builder --mode cli \
      --origin built --rc 0 --step-name cli --dest "${dest}" "$@" \
      >/dev/null 2>&1 || rc="$?"
   printf '%s' "${rc}"
}

## True iff the sentinel appears in an (optionally absent) result.json.
leaked() {
   local json="$1"
   if [ -f "${json}" ] && grep --quiet --fixed-strings -- "${sentinel}" "${json}"; then
      printf yes
   else
      printf no
   fi
}

## 1. A genuine regular stderr file is read and its tail recorded.
out1="${workdir}/r1.json"
check "regular stderr file accepted" \
   "$(emit_rc "${out1}" --step-stderr-file "${workdir}/err.txt")" '0'
check "regular stderr tail recorded" \
   "$(grep --quiet --fixed-strings -- 'genuine stderr tail' "${out1}" && printf yes || printf no)" 'yes'

## 2. A symlinked stderr file is REFUSED but the run is still published (exit 0): the
##    target never reaches the output and the tail is empty. The account cannot
##    suppress its own result by planting a symlink.
##    (Canary: the pre-fix emitter followed the symlink and leaked the target.)
out2="${workdir}/r2.json"
check "symlinked stderr file does not abort the publish" \
   "$(emit_rc "${out2}" --step-stderr-file "${workdir}/err.symlink")" '0'
check "symlinked stderr target not leaked" \
   "$(leaked "${out2}")" 'no'

## 3. A symlinked screenshot source is likewise refused, no leak, publish still OK and
##    no attachment recorded.
out3="${workdir}/r3.json"
check "symlinked shot-src does not abort the publish" \
   "$(emit_rc "${out3}" --step-shot cli.png --step-shot-src "${workdir}/shot.symlink")" '0'
check "symlinked shot target not leaked" \
   "$(leaked "${out3}")" 'no'
check "symlinked shot records no attachment" \
   "$(grep --quiet --fixed-strings -- '"attachments": []' "${out3}" && printf yes || printf no)" 'yes'

## 4. A genuine regular screenshot is copied into the result dir and attached.
out4="${workdir}/r4.json"
check "regular shot-src accepted" \
   "$(emit_rc "${out4}" --step-shot cli.png --step-shot-src "${workdir}/shot.png")" '0'
check "regular shot copied into result dir" \
   "$([ -f "${workdir}/cli.png" ] && printf yes || printf no)" 'yes'

## 5. A missing screenshot source is the normal 'no shot this run': clean, no attachment.
out5="${workdir}/r5.json"
check "missing shot-src is a clean no-shot" \
   "$(emit_rc "${out5}" --step-shot cli.png --step-shot-src "${workdir}/absent.png")" '0'
check "missing shot-src records no attachment" \
   "$(grep --quiet --fixed-strings -- '"attachments": []' "${out5}" && printf yes || printf no)" 'yes'

## 6. An oversized screenshot (beyond the cap) is dropped: no attachment, no partial
##    copy, the run still published. Cap lowered via the env seam so the fixture is
##    tiny; an isolated dest dir so the check sees only this run's copy.
mkdir --parents -- "${workdir}/d6"
out6="${workdir}/d6/r6.json"
printf '%s' 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > "${workdir}/big.png"
rc6=0
IMAGE_TEST_MAX_SHOT_BYTES=8 "${emit}" \
   --run-id r-1 --lane testlane --builder builder --mode cli \
   --origin built --rc 0 --step-name cli --dest "${out6}" \
   --step-shot cli.png --step-shot-src "${workdir}/big.png" >/dev/null 2>&1 || rc6=$?
check "oversized shot does not abort the publish" "${rc6}" '0'
check "oversized shot records no attachment" \
   "$(grep --quiet --fixed-strings -- '"attachments": []' "${out6}" && printf yes || printf no)" 'yes'
check "oversized shot leaves no partial copy" \
   "$([ -e "${workdir}/d6/cli.png" ] && printf exists || printf absent)" 'absent'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
