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

## A bad INDIVIDUAL shot must SKIP that attachment, never abort the whole emit -- else
## an untrusted account could suppress its own result.json by planting one odd *.png
## next to the real milestones. Two genuine sources to pair bad shots with a good one.
printf '%s' 'GOOD-ONE' > "${workdir}/good1.png"
printf '%s' 'GOOD-TWO' > "${workdir}/good2.png"

## 7. A duplicate --step-shot-name is SKIPPED (one attachment kept), publish still OK.
##    (Canary: the pre-fix emitter `return 2`'d and wrote NO result.json.)
out7="${workdir}/d7/r7.json"
mkdir --parents -- "${workdir}/d7"
check "duplicate shot name does not abort the publish" \
   "$(emit_rc "${out7}" \
      --step-shot a.png --step-shot-src "${workdir}/good1.png" --step-shot-name dup \
      --step-shot b.png --step-shot-src "${workdir}/good2.png" --step-shot-name dup)" '0'
check "duplicate shot name kept exactly once" \
   "$(grep --count --fixed-strings -- '"name": "dup"' "${out7}")" '1'

## 8. An unsafe --step-shot-name (a control char) is SKIPPED, a co-emitted good shot
##    is still recorded, and result.json is written.
out8="${workdir}/d8/r8.json"
mkdir --parents -- "${workdir}/d8"
check "unsafe shot name does not abort the publish" \
   "$(emit_rc "${out8}" \
      --step-shot bad.png --step-shot-src "${workdir}/good1.png" --step-shot-name "$(printf 'bad\tname')" \
      --step-shot ok.png --step-shot-src "${workdir}/good2.png" --step-shot-name good)" '0'
check "unsafe shot name skipped, good shot kept" \
   "$(grep --quiet --fixed-strings -- '"name": "good"' "${out8}" \
      && ! grep --quiet --fixed-strings -- '"name": "bad' "${out8}" && printf yes || printf no)" 'yes'

## 9. Two shots with the SAME stored basename: the second is skipped, so it cannot
##    TRUNCATE the first; the stored file keeps the first shot's bytes, publish OK.
out9="${workdir}/d9/r9.json"
mkdir --parents -- "${workdir}/d9"
check "duplicate stored basename does not abort the publish" \
   "$(emit_rc "${out9}" \
      --step-shot same.png --step-shot-src "${workdir}/good1.png" --step-shot-name one \
      --step-shot same.png --step-shot-src "${workdir}/good2.png" --step-shot-name two)" '0'
check "duplicate stored basename keeps the first shot's bytes" \
   "$(cat -- "${workdir}/d9/same.png")" 'GOOD-ONE'
check "duplicate stored basename records one attachment path" \
   "$(grep --count --fixed-strings -- '"path": "same.png"' "${out9}")" '1'

## 10. PARENT-DIR TOCTOU: O_NOFOLLOW guards only the LEAF, so a bare open of a full
##     path still resolves the PARENT through a symlink. The adversary owns the shot
##     dir and can swap it to a symlink AFTER enumeration, redirecting root's read into
##     a root-only tree. The emitter must open the parent no-follow + openat the leaf,
##     so a symlinked parent is REFUSED (no copy, no leak), run still published.
##     Canary: a regular leaf inside a SYMLINKED parent dir. Pre-fix (bare O_NOFOLLOW on
##     the full path) followed the parent symlink and COPIED the sentinel.
realparent="${workdir}/realparent"
mkdir --parents -- "${realparent}"
printf '%s\n' "${sentinel}" > "${realparent}/leaf.png"
ln --symbolic -- "${realparent}" "${workdir}/symparent"
out10="${workdir}/d10/r10.json"
mkdir --parents -- "${workdir}/d10"
check "symlinked parent dir does not abort the publish" \
   "$(emit_rc "${out10}" --step-shot leaf.png --step-shot-src "${workdir}/symparent/leaf.png")" '0'
check "symlinked parent dir -- leaf NOT copied (records no attachment)" \
   "$(grep --quiet --fixed-strings -- '"attachments": []' "${out10}" && printf yes || printf no)" 'yes'
## The real leak is the COPIED file in the world-readable plane, not the json text:
## grep the whole run dir for the sentinel (pre-fix copied realparent/leaf.png there).
check "symlinked parent dir -- sentinel NOT leaked into the plane" \
   "$(grep --quiet --recursive --fixed-strings -- "${sentinel}" "${workdir}/d10" 2>/dev/null && printf LEAKED || printf no)" 'no'

## 11. A DROPPED first shot (oversized -> copy skips it) must NOT reserve its milestone,
##     so a valid same-milestone retake is still emitted (not skipped as a dup). The
##     publisher strips the NN- prefix, so 00-welcome and 01-welcome both map to
##     'welcome'. Pre-fix reserved the name BEFORE copy_shot, losing the milestone.
out11="${workdir}/d11/r11.json"
mkdir --parents -- "${workdir}/d11"
printf '%s' 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > "${workdir}/oversize.png"
rc11=0
IMAGE_TEST_MAX_SHOT_BYTES=8 "${emit}" \
   --run-id r-1 --lane testlane --builder builder --mode cli \
   --origin built --rc 0 --step-name cli --dest "${out11}" \
   --step-shot 00-welcome.png --step-shot-src "${workdir}/oversize.png" --step-shot-name welcome \
   --step-shot 01-welcome.png --step-shot-src "${workdir}/good1.png" --step-shot-name welcome \
   >/dev/null 2>&1 || rc11=$?
check "dropped first shot does not abort the publish" "${rc11}" '0'
check "dropped first shot -- same-milestone retake still emitted" \
   "$(grep --count --fixed-strings -- '"name": "welcome"' "${out11}")" '1'
check "dropped first shot -- retake stored, oversize not" \
   "$([ -f "${workdir}/d11/01-welcome.png" ] && [ ! -f "${workdir}/d11/00-welcome.png" ] && printf yes || printf no)" 'yes'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
